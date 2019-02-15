postgres-proxy
--------------
This is a postgres connection proxy that looks up the owner of the socket
(TCP-ident-style or UNIX-SO\_PEERCRED) and provides the postgresql password
automatically.

TCP-ident-style: think `netstat -p` or oidentd; here it's implemented with
netlink sockets. UNIX-SO\_PEERCRED: this is a syscall you can use to ask which
process/uid/gid is on the other end of a UNIX socket. 

PostgreSQL supports both of these (the `ident` authentication method). However,
UNIX-socket-ident requires the client to be on the same machine, and TCP-ident
requires you to trust the network between you and the client. Furthermore, in my
case I did not want to issue users passwords.

So, the proxy runs on the local machine that users are connected on, privileged,
and has access to a password database. It accepts connections on a local unix
socket or TCP localhost, checks which local user owns the connection, and then
looks up the password in the database. It then uses that password to connect
upstream, proxying the rest of the connection.

In practice, this means we 

 - read the StartupMessage
 - check that the owner of the other end of the socket matches the role in the
   StartupMessage
 - connect upstream (replaying the same StartupMessage), checking that the
   server requests a password and then injecting the password
 - switch to just passing bytes back and forth

In particular, the response to the injected password message can just be passed
verbatim back to the client, since it will either be a authentication-ok or
error response, exactly what the client was expecting in response to its startup
message. So we switch to passing bytes back and forth without inspecting the
response to the injected password.

Since we only need to implement a couple message types of the PostgreSQL and
netlink protocols, neither are particularly well abstracted, it's just a single
file with the one-off bits required. Good luck.
