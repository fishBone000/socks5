# Under Construction, Preview ONLY
# SOCKSY5
Socksy5 provides a Golang SOCKS5 middle layer that handle communication with clients 
itself, but let you to do decision on what to do with the handshakes and requests. 

### What it does: 
- Reading requests and sending replies
- Wrap requests and provide methods for accepting and rejecting them
- Attach connection from external code for CONNECT, BIND requests
- Emitting different types of log entries 
- Support multi-homed BINDing and UDP ASSOCIATEing

### What it requires you to do: 
- Decision on accepting / rejecting incoming client handshake and requests
- Select which auth method and subnegotiation to use (supports custom)
- Dial and pass outbound connections to the middle layer (CONNECT)
- Listen for connections from application servers (BIND)
- UDP relaying (UDP ASSOCIATE)
- Writing log to console or files

### Some other implementation in this module:
- Connector for CONNECT and outbound dialing
- Binder for BIND and listening for incoming connection
- Associator for UDP ASSOCIATE and UDP relaying
- NoAuthSubneg for NO AUTHENTICATION subnegotiation
- UsrPwdSubneg for USERNAME/PASSWORD subnegotiation
- NoCap for no encapsulation/decapsulation

For details, see the Go reference. 

## Note
- Issues, suggestions and PRs welcome
- Way much less maintainance after September 2023
