import asyncio
import collections
import os
import pwd as passwd_database
import socket
import struct
import sys

class PostgresProtocolError(Exception):
    def __init__(self, sentence, **kwargs):
        self.sentence = sentence
        self.kwargs = kwargs
        
    def __str__(self):
        return f"{self.sentence}: {self.kwargs}"

class PostgresStartup:
    def __init__(self, rawmsg, kind, args):
        self.rawmsg = rawmsg
        self.kind = kind
        self.args = args

    header_format = ">iHH"
    header_length = struct.calcsize(header_format)

    @classmethod
    async def read(cls, reader):
        header = await reader.readexactly(cls.header_length)
        total_length, major, minor = struct.unpack(cls.header_format, header)

        if major == 1234 and minor == 5679:
            if total_length != cls.header_length:
                raise PostgresProtocolError("SSLRequest unexpectedly long")

            return cls(rawmsg=header, kind="SSLRequest", args={})

        elif major == 1234 and minor == 5678:
            if total_length != cls.header_length + 8:
                raise PostgresProtocolError("CancelRequest unexpectedly long")

            payload = await reader.readexactly(8)
            return cls(rawmsg=header + payload, kind="CancelRequest", args={})

        elif major == 3 and minor == 0:
            payload = await reader.readexactly(total_length - cls.header_length)

            bits = payload.split(b"\x00")

            if len(bits) % 2 != 0 or bits[-2:] != [b'', b'']:
                raise PostgresProtocolError("bad startup pairs", bits=bits)

            args = {}

            for i in range(0, len(bits) - 2, 2):
                key = bits[i]
                value = bits[i + 1]
                if key in args:
                    raise PostgresProtocolError("duplicate startup key", key=key)

                args[key] = value

            return cls(rawmsg=header + payload, kind="StartupMessage", args=args)

        else:
            raise PostgresProtocolError("Bad version", 
                    header=header,
                    major=major, 
                    minor=minor)

class PostgresAuthenticationRequest:
    TYPE_CHAR = b'R'

    OK = 0
    CLEARTEXT_PASSWORD = 3

    def __init__(self, code):
        self.code = code

    @classmethod
    def unpack(cls, payload):
        code, = struct.unpack_from(">i", payload)
        return cls(code)

class PostgresErrorResponse:
    TYPE_CHAR = b'E'

    def __init__(self, args):
        self.args = args
    
    def __repr__(self):
        return repr(self.args)

    @classmethod
    def simple(cls, message):
        return cls({b"S": b"ERROR",
                    b"V": b"ERROR",
                    b"C": b"08000",
                    b"M": message.encode("utf8")})

    def pack(self):
        return b''.join(k + v + b'\x00' for k, v in self.args.items()) + b'\x00'

    @classmethod
    def unpack(cls, payload):
        bits = payload.split(b'\x00')
        if bits[-2:] != [b'', b'']:
            raise PostgresProtocolError("bad error response bits", bits=bits)
        return cls({b[0:1]: b[1:] for b in bits[:-2]})

    def get_reason_or_default(self):
        try:
            return resp.args[b"M"].decode("ascii")
        except:
            return "(unable to retrieve reason)"

class PostgresPasswordMessage:
    TYPE_CHAR = b'p'

    def __init__(self, payload):
        self.payload = payload

    def pack(self):
        return self.payload + b"\x00"

async def read_tagged_postgres_message(reader):
    header = await reader.readexactly(5)
    type_char, length = struct.unpack(">ci", header)
    payload = await reader.readexactly(length - 4)

    if type_char == PostgresAuthenticationRequest.TYPE_CHAR:
        return PostgresAuthenticationRequest.unpack(payload)
    elif type_char == PostgresErrorResponse.TYPE_CHAR:
        return PostgresErrorResponse.unpack(payload)
    else:
        raise PostgresProtocolError("Unrecognised message type", type_char=type_char)

def write_tagged_postgres_message(writer, message):
    payload = message.pack()
    writer.write(struct.pack(">ci", message.TYPE_CHAR, len(payload) + 4))
    writer.write(payload)

NETLINK_INET_DIAG = 4

_NetlinkHeader = collections.namedtuple("_NetlinkHeader", 
        ["total_length", "type", "flags", "seq", "pid"])
class NetlinkHeader(_NetlinkHeader):
    NLMSG_NOOP = 1
    NLMSG_ERROR = 2
    NLMSG_DONE = 3  
    SOCK_DIAG_BY_FAMILY = 20
    NLM_F_REQUEST = 1
    NLM_F_DUMP = 0x100 | 0x200

    format = "=IHHII"
    length = struct.calcsize(format)

    def pack(self):
        return struct.pack(self.format, *self)

    @classmethod
    def sock_diag_request(cls, payload_len):
        return cls(total_length=cls.length + payload_len,
                type=cls.SOCK_DIAG_BY_FAMILY,
                flags=cls.NLM_F_REQUEST | cls.NLM_F_DUMP,
                seq=0, 
                pid=0)

    @classmethod
    def unpack_from(cls, buffer, offset):
        return cls(*struct.unpack_from(cls.format, buffer, offset))

class NetlinkError(OSError):
    @classmethod
    def unpack_from(cls, buffer, offset):
        errno, = struct.unpack_from("=i", buffer, offset)
        return cls(-errno, os.strerror(-errno))

_NetlinkInetDiagSockid = collections.namedtuple("_NetlinkInetDiagSockid",
        ["sport", "dport", "src", "dst", "intf", "cookie"])
class NetlinkInetDiagSockid(_NetlinkInetDiagSockid):
    format_bits = [">HH16s16s", "=i8s"]
    length_bits = [struct.calcsize(b) for b in format_bits]
    length = sum(length_bits)
    assert length == 48

    def pack(self):
        f1, f2 = self.format_bits
        d1, d2 = self[:4], self[4:]
        return struct.pack(f1, *d1) + struct.pack(f2, *d2) 

    @classmethod
    def unpack(cls, bytes):
        if len(bytes) != cls.length:
            raise Exception("NetlinkInetDiagSockid: bad length")

        f1, f2 = cls.format_bits
        l1, _l2 = cls.length_bits
        
        args = struct.unpack_from(f1, bytes) + struct.unpack_from(f2, bytes, offset=l1)

        return cls(*args)

_NetlinkInetDiagReq = collections.namedtuple("_NetlinkInetDiagReq",
        ["family", "protocol", "ext", "states", "id"])
class NetlinkInetDiagReq(_NetlinkInetDiagReq):
    format = f"=bbbxI{NetlinkInetDiagSockid.length}s"
    length = struct.calcsize(format)

    TCP_ESTABLISHED = 1

    def pack(self):
        bits = self[:-1] + (NetlinkInetDiagSockid.pack(self[-1]), )
        return struct.pack(self.format, *bits)

    @classmethod
    def tcp4_established_port_search(cls, sport, dport):
        return cls(
            family=socket.AF_INET, 
            protocol=socket.IPPROTO_TCP,
            ext=0, 
            states=(1 << cls.TCP_ESTABLISHED), 
            id=NetlinkInetDiagSockid(
                sport=sport,
                dport=dport, 
                src=b"",
                dst=b"",
                intf=0, 
                cookie=b""))

_NetlinkInetDiagMsg = collections.namedtuple("_NetlinkInetDiagMsg",
        ["family", "state", "timer", "retrans", "id", 
            "expires", "rqueue", "wqueue", "uid", "inode"])
class NetlinkInetDiagMsg(_NetlinkInetDiagMsg):
    format = f"=bbbb{NetlinkInetDiagSockid.length}sIIIII"

    @classmethod
    def unpack_from(cls, buffer, offset):
        bits = struct.unpack_from(cls.format, buffer, offset)
        bits = bits[:4] + (NetlinkInetDiagSockid.unpack(bits[4]), ) + bits[5:]
        return cls(*bits)

_StructUCred = collections.namedtuple("_StructUCred", ["pid", "uid", "gid"])
class StructUCred(_StructUCred):
    format = "=iii"
    length = struct.calcsize(format)

    @classmethod
    def unpack(cls, buffer):
        return cls(*struct.unpack(cls.format, buffer))

    @classmethod
    def getpeercred(cls, sock):
        r = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, cls.length)
        return cls.unpack(r)

class NetlinkSocket:
    def __init__(self):
        self.sock = socket.socket(
                socket.AF_NETLINK, 
                socket.SOCK_DGRAM, 
                NETLINK_INET_DIAG)
    
    async def _one_shot_request(self, request):
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self.sock, request)

        while True:
            payload = await loop.sock_recv(self.sock, 65535) 
            offset = 0

            while offset < len(payload):
                header = NetlinkHeader.unpack_from(payload, offset)
                payload_offset = offset + NetlinkHeader.length

                if header.type == NetlinkHeader.NLMSG_ERROR:
                    raise NetlinkError.unpack_from(payload, offset=payload_offset)
                elif header.type == NetlinkHeader.NLMSG_DONE:
                    return
                elif header.type == NetlinkHeader.SOCK_DIAG_BY_FAMILY:
                    yield NetlinkInetDiagMsg.unpack_from(payload, offset=payload_offset)
                    offset += header.total_length

    async def one_shot_request(self, request):
        aiter = self._one_shot_request(request).__aiter__()

        try:
            async for result in aiter:
                yield result
        finally:
            # We must pull everything out of the socket until the Done message.
            async for _discard in aiter:
                pass

async def copy_bytes(reader, writer):
    while not reader.at_eof():
        b = await reader.read(65535)
        writer.write(b)
        await writer.drain()
    writer.write_eof()

class AuthenticationFailed(Exception): pass

class Client:
    def __init__(self, reader, writer, log_tag):
        self.reader = reader
        self.writer = writer
        self.log_tag = log_tag

    def log(self, *message):
        print(self.log_tag, *message)

class BaseServer:
    def __init__(self, upstream, password_database):
        self.upstream = upstream
        self.password_database = password_database

    @staticmethod
    async def getpwuid(uid):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, passwd_database.getpwuid, uid)

    @staticmethod
    def write_simple_error(client, message):
        client.log(message)
        resp = PostgresErrorResponse.simple(message)
        write_tagged_postgres_message(client.writer, resp)

    def log_tag(self, writer):
        raise NotImplementedError

    async def get_peer_uid(self, writer):
        raise NotImplementedError

    async def skip_ssl_request_and_get_startup_message(self, client):
        startup_message = await PostgresStartup.read(client.reader)

        if startup_message.kind == "SSLRequest":
            # deny the SSL request:
            writer.write(b"N")

            # read the new startup message
            startup_message = await PostgresStartup.read(client.reader)

        if startup_message.kind == "SSLRequest":
            raise PostgresProtocolError("Duplicate SSL Requests")

        return startup_message

    async def get_and_check_peer_username(self, client, startup_message):
        socket_uid = await self.get_peer_uid(client.writer)

        try:
            socket_passwd = await self.getpwuid(socket_uid)
        except Exception as e:
            raise AuthenticationFailed("UID lookup failed", socket_uid, e)

        socket_username = socket_passwd.pw_nam
        client.log("socket username is", socket_uid, socket_username)

        if b"user" not in startup_message.args:
            raise PostgresProtocolError("No username in startup")

        try:
            login_username = startup_message.args[b"user"].decode("ascii")
        except UnicodeDecodeError:
            raise PostgresProtocolError("username is not ascii")

        if login_username != socket_username:
            message = f"username mismatch: you are {socket_username}, " \
                    f"you sent {login_username}"
            raise AuthenticationFailed(message)

        if socket_username not in self.password_database:
            message = f"no entry for {socket_username} in password database"
            raise AuthenticationFailed(message)

        return socket_username

    async def really_handle_connection(self, client)
        startup_message = await self.skip_ssl_request_and_get_startup_message(client)

        if startup_message.kind == "CancelRequest":
            client.log("Passing on cancel request")
            try:
                # TODO: this needs to be "with connection"...
                upstream_reader, upstream_writer = \
                        await asyncio.open_connection(*self.upstream)
            except Exception as e:
                client.log("Passing on cancel request failed", e)
            else:
                # TODO: can this raise?
                upstream_writer.write(startup_message.rawmsg)
                upstream_writer.close()
            finally:
                return

        if startup_message.kind != "StartupMessage":
            raise Exception("BUG: failed to match on startup_message.kind", startup_message.kind)

        try:
            username = await self.get_and_check_peer_username(client.writer, startup_message)
        except AuthenticationFailed as e:
            message = f"authentication failed: {e}"
            self.write_simple_error(client.writer, message)
            return

        client.log("Acceptable username, connecting upstream", username)

        try:
            # TODO: this needs to be "with connection"...
            upstream_reader, upstream_writer = \
                    await asyncio.open_connection(*self.upstream)
        except Exception as e:
            message = f"postgres proxy failed to connect upstream: {e}"
            self.write_simple_error(client.writer, message)
            return

        # TODO: can this raise?
        upstream_writer.write(startup_message.rawmsg)

        resp = await read_tagged_postgres_message(upstream_reader)

        if isinstance(resp, PostgresErrorResponse):
            reason = resp.get_reason_or_default()
            client.log("Upstream returned an error immediately:", reason)
            write_tagged_postgres_message(client.writer, resp)
            return

        if not isinstance(resp, PostgresAuthenticationRequest):
            message = "Unexpected message type from upstream, wanted auth request"
            self.write_simple_error(client.writer, message)
            return

        if resp.code != PostgresAuthenticationRequest.CLEARTEXT_PASSWORD:
            message = "upstream did not want to perform password auth"
            self.write_simple_error(client.writer, message)
            return

        client.log("Injecting password and switching to passthrough")

        postgres_password = self.password_database[username]
        password_message = PostgresPasswordMessage(postgres_password)
        write_tagged_postgres_message(upstream_writer, password_message)

        await asyncio.gather(
                copy_bytes(client.reader, upstream_writer),
                copy_bytes(upstream_reader, client.writer))

    async def handle_connection(self, reader, writer):
        log_tag = self.log_tag(writer)
        client = Client(reader, writer, log_tag)

        client.log("Received connection")

        try:
            await self.really_handle_connection(client)
        except PostgresProtocolError as e:
            client.log("Protocol Error", e)
        except asyncio.IncompleteReadError as e:
            client.log("EOF", e)
        except Exception as e:
            asyncio.get_running_loop().stop()
            raise e
        finally:
            client.log("Connection done")
            writer.close()

class TCPServer(BaseServer):
    def __init__(self, listen_port, **others):
        super().__init__(**others)
        self.listen_port = listen_port
        self.netlink_socket = NetlinkSocket()

    def log_tag(self, writer):
        peername = writer.get_extra_info('peername')
        return f"TCP:{peername[0]}:{peername[1]}" 

    localhost_a = "127.0.0.1"
    localhost_n = socket.inet_aton(localhost_a)
    expect_diag_addr = localhost_n + b"\x00" * 12

    async def get_peer_uid(self, writer):
        peer_addr, peer_port = writer.get_extra_info('peername')
        peer_addr = socket.inet_aton(peer_addr) # only works on v4.
        
        if peer_addr != self.localhost_n:
            raise AuthenticationFailed("peer_addr was not localhost")

        req_payload = NetlinkInetDiagReq.tcp4_established_port_search(
                sport=peer_port, 
                dport=self.listen_port).pack()

        req = NetlinkHeader.sock_diag_request(len(req_payload)).pack() + req_payload

        async for sock in self.netlink_socket.one_shot_request(req):
            if sock.id.src != self.expect_diag_addr:
                continue
            
            if sock.id.dst != self.expect_diag_addr:
                continue

            return sock.uid

        else:
            raise AuthenticationFailed("Failed to find peer socket")

    async def start_serving(self):
        self.tcp_server = await asyncio.start_server(
            self.handle_connection, '127.0.0.1', self.listen_port)

        await self.tcp_server.start_serving()

class UnixServer(BaseServer):
    def __init__(self, path, **others):
        super().__init__(**others)
        self.path = path

    def log_tag(writer):
        sock = writer.get_extra_info('socket')
        return f"UNIX:{sock.fileno()}"

    async def get_peer_uid(self, writer):
        sock = writer.get_extra_info('socket')

        try:
            cred = StructUCred.getpeercred(sock)
        except Exception as e:
            raise AuthenticationFailed("getpeercred failed", e)

        return cred.uid
    
    async def start_serving(self):
        self.unix_server = await asyncio.start_unix_server(
                self.handle_connection, self.path)

        os.chmod(self.path, 0o777)

        await self.unix_server.start_serving()

def main():
    common_args = {"upstream": ("localhost", 5432), 
            "password_database": {"www-tickets": b"moo"}}
    tcp_server = TCPServer(listen_port=5433, **common_args)
    unix_server = UnixServer(path="/tmp/.s.PGSQL.5433", **common_args)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_server.start_serving())
    loop.run_until_complete(unix_server.start_serving())
    print("Listening")
    loop.run_forever()
    sys.exit(1)

if __name__ == "__main__":
    main()
