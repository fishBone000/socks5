# Under Construction
# socks5-server-interface (s5i)
This is a SOCKS5 server partial implementation. 

Unlike regular SOCKS5 servers, it lets external code handle many stuff:
- Decision on accepting / rejecting incoming client handshake and requests
- Auth method subnegotiation (supports custom)
- Per auth method traffic encapsulation / decapsulation (also supports custom)
- Outbound dialing for CONNECT request
- Writing log to console or files
- UDP relaying

And it does:
- Reading requests and sending replies
- Wrap requests and provide methods for accepting and rejecting them
- Attach connection from external code for CONNECT, BIND requests
- Emitting different types of log entries 
- Support multi-homed BINDing and UDP ASSOCIATing

Also there's some implementation in this module:
- Connector for CONNECT and outbound dialing
- Binder for BIND and listening for incoming connection
- Associator for UDP ASSOCIATE and UDP relaying
- NoAuthSubneg for NO AUTHENTICATION subnegotiation
- UsrPwdSubneg for USERNAME/PASSWORD subnegotiation
- NoCap for no encapsulation/decapsulation

Note:
- Issues and PRs welcome, email me before making big PR though
- Way much less maintainance after September 2023
