# Under Construction
# socks5-server-interface (s5i)
This is a SOCKS5 server partial implementation. 

Unlike regular SOCKS5 servers, it lets external code handle many stuff:
- Decision on accepting / rejecting incoming client handshake and requests
- Auth method subnegotiation
- Per auth method traffic encapsulation / decapsulation
- Outbound dialing for CONNECT request
- Writing log to console or files

And it does:
- Reading requests and sending replies
- Wrap requests and provide methods for accepting and rejecting them
- Attach connection from external code for CONNECT, BIND requests
- UDP relaying
- Emitting different types of log entries 
- Support multi-homed BINDing and UDP ASSOCIATing

Also there's some implementation in this module:
- Connector for CONNECT
- Binder for BIND
- Associator for UDP ASSOCIATE
- NoAuthSubneg for NO AUTHENTICATION subnegotiation
- UsrPwdSubneg for USERNAME/PASSWORD subnegotiation

Note:
- The server interface might emit failed to close conn/listener warnings, even if the cause is the conn/listener has been already closed. 
