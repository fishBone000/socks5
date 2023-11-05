[![Go Reference](https://pkg.go.dev/badge/github.com/fishBone000/socksy5.svg)](https://pkg.go.dev/github.com/fishBone000/socksy5)

# SOCKSY5
Socksy5 provides a Golang SOCKS5 middle layer that handle communication with clients 
for you, but let you to do decision on what to do with the handshakes and requests. 

### What the middle layer does: 
- Reading requests and sending replies
- Wrap requests and provide methods for accepting and rejecting them
- Attach connection from external code for CONNECT, BIND requests
- Emitting different types of log entries 
- Support multi-homed BINDing and UDP ASSOCIATEing

### What the middle layer requires you to do: 
- Decision on accepting / rejecting incoming client handshake and requests
- Select which auth method and subnegotiation to use (supports custom)
- Dial and pass outbound connections to the middle layer (CONNECT)
- Listen for connections from application servers (BIND)
- UDP relaying (UDP ASSOCIATE)
- Writing logs to the console or files

#### If you want to make a SOCKS5 server fast, read on. 

### Some other implementation in this module:
- Func Connect for CONNECT and outbound dialing. 
- Binder for BIND and listening for incoming connection. 
- Associator for UDP ASSOCIATE and UDP relaying. 
- NoAuthSubneg for NO AUTHENTICATION subnegotiation. 
- UsrPwdSubneg for USERNAME/PASSWORD subnegotiation. 
- NoCap for no encapsulation/decapsulation. 

For details, see the Go reference. 

## Note
- Issues, suggestions and PRs welcome
- I will be busy for quite a long time, expect less maintanence. 
- It's still in unstable release, expect:
  - Weird error and log util design
    - If you have better ideas, submit issues!
  - Potential bugs
    - I use a SOCKS5 proxy which is based on socksy5 for daily use, so it's not...that buggy. 
