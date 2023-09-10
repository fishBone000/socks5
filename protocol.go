package s5i

import (
	"io"
	"net"
	"sync"
)

const VerSOCKS5 byte = 0x05 // SOCKS5 VER byte

// Authentication METHOD codes.
const (
	MethodNoAuth byte = 0x00
	MethodGSSAPI byte = 0x01
	MethodUsrPwd byte = 0x02
	MethodCHAP   byte = 0x03

	MethodCRAM byte = 0x05
	MethodSSL  byte = 0x06
	MethodNDS  byte = 0x07
	MethodMAF  byte = 0x08
	MethodJRB  byte = 0x09

	MethodNoAccepted byte = 0xFF
)

// CMD codes
const (
	CmdCONNECT byte = 0x01
	CmdBIND    byte = 0x02
	CmdASSOC   byte = 0x03
)

const RSV byte = 0x00 // Value of reserved bytes

// ATYP codes (address types), IP V4, DOMAINNAME and IP V6
const (
	ATYPV4     byte = 0x01
	ATYPDOMAIN byte = 0x03
	ATYPV6     byte = 0x04
)

// REP reply codes
const (
	RepSucceeded               byte = 0x00
	RepGeneralFailure          byte = 0x01
	RepConnNotAllowedByRuleset byte = 0x02
	RepNetworkUnreachable      byte = 0x03
	RepHostUnreachable         byte = 0x04
	RepConnRefused             byte = 0x05
	RepTtlExpired              byte = 0x06
	RepCmdNotSupported         byte = 0x07
	RepAddrTypeNotSupported    byte = 0x08
)

// Addr stands for addresses sent in SOCKS5 requests and replies.
type Addr struct {
	Type  byte   // ATYP byte value
	Bytes []byte // Raw bytes
}

func readAddr(reader io.Reader) (*Addr, error) {
	atyp, err := readByte(reader)
	if err != nil {
		return &Addr{}, err
	}
	var content []byte
	switch atyp {
	case ATYPV4:
		content = make([]byte, 4)
	case ATYPV6:
		content = make([]byte, 16)
	case ATYPDOMAIN:
		l, err := readByte(reader)
		if err != nil {
			return &Addr{}, err
		}
		content = make([]byte, 1+l)
	default:
		return &Addr{}, ErrMalformed
	}
	if atyp == ATYPDOMAIN {
		_, err = fillBuffer(content[1:], reader)
	} else {
		_, err = fillBuffer(content, reader)
	}
	if err != nil {
		return &Addr{}, err
	}
	return &Addr{
		Type:  atyp,
		Bytes: content,
	}, nil
}

// Returns "ip4" if ATYP byte value is ATYPV4, "ip6" if ATYPV6,
// "fqdn" if ATYPDOMAIN, which stands for fully-qualified domain name,
// "unknown" otherwise.
func (a *Addr) Network() string {
	switch a.Type {
	case ATYPV4:
		return "ip4"
	case ATYPV6:
		return "ip6"
	case ATYPDOMAIN:
		return "fqdn"
	}
	return "unknown"
}

func (a *Addr) String() string {
	if a.Type == ATYPV4 || a.Type == ATYPV6 {
		return net.IP(a.Bytes).String()
	}
	return string(a.Bytes)
}

func (a *Addr) cpy() *Addr {
	b := new(Addr)
	b.Type = a.Type
	b.Bytes = make([]byte, len(a.Bytes))
	copy(b.Bytes, a.Bytes)
	return b
}

type HandshakeRequest struct {
	ver          byte
	nmethods     byte
	methods      []byte
	methodChosen byte

	wg   *sync.WaitGroup
	once *sync.Once
	neg  Subnegotiator
}

func readHandshakeRequest(reader io.Reader) (HandshakeRequest, error) {
	req := HandshakeRequest{
		wg:   new(sync.WaitGroup),
		once: new(sync.Once),
	}
	var err error
	req.ver, err = readByte(reader)
	if err != nil {
		return HandshakeRequest{}, err
	}
	if req.ver != VerSOCKS5 {
		return HandshakeRequest{}, ErrMalformed
	}
	req.nmethods, err = readByte(reader)
	if err != nil {
		return HandshakeRequest{}, err
	}
	req.methods = make([]byte, req.nmethods)
	_, err = fillBuffer(req.methods, reader)
	if err != nil {
		return HandshakeRequest{}, err
	}
	return req, nil
}

// RequestMsg contains common info of all types of requests, like CMD and DST.
// Use ConnectRequest e.t.c. for manipulation.
type RequestMsg struct {
	cmd     byte
	dstAddr *Addr
	dstPort uint16 // Native byte order

	raddr net.Addr
	laddr net.Addr
	once  *sync.Once
	wg    *sync.WaitGroup
}

func readRequest(reader io.Reader) (*RequestMsg, error) {
	ver, err := readByte(reader)
	if err != nil {
		return nil, err
	}
	if ver != VerSOCKS5 {
		return nil, ErrMalformed
	}

	req := new(RequestMsg)
	req.cmd, err = readByte(reader)
	if err != nil {
		return nil, err
	}

	rsv, err := readByte(reader)
	if err != nil {
		return nil, err
	}
	if rsv != RSV {
		return nil, ErrMalformed
	}

	req.dstAddr, err = readAddr(reader)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (r *RequestMsg) wait() {
	r.wg.Wait()
}

func (r *RequestMsg) add(delta int) {
	r.wg.Add(delta)
}

func (r *RequestMsg) done() {
  r.wg.Done()
}

func (r *RequestMsg) LocalAddr() net.Addr {
	return r.laddr
}

func (r *RequestMsg) RemoteAddr() net.Addr {
	return r.raddr
}

func (r *RequestMsg) DstAddr() *Addr {
	return r.dstAddr.cpy()
}

func (r *RequestMsg) DstPort() uint16 {
	return r.dstPort
}

type ConnectRequest struct {
	RequestMsg
	conn net.Conn
}

// Accepts the request, and starts proxying.
// Request is denied if param conn is nil.
func (r *ConnectRequest) Accept(conn net.Conn) {
}

// Denies the request with REP byte code.
func (r *ConnectRequest) Deny(rep byte) {
}

type BindRequest struct {
	RequestMsg
}

// Accepts the request, and tells the client which address the SOCKS server
// will listen on. This is the first reply from the server.
// Note that s5i doesn't actually listens it for you. You can implement a
// listener yourself or use Binder.
// Mutli-homed binding is allowed.
func (r *BindRequest) Accept(addr string) {
}

// Binds the client. This is the second reply from the server.
// The server interface will pipe the conn for you.
func (r *BindRequest) Bind(conn net.Conn) {
}

// Denies the request with REP byte code.
func (r *BindRequest) Deny(rep byte) {
}

type AssocRequest struct {
	RequestMsg
}

// Accepts the request. Note that s5i doesn't actually relays the UDP traffic.
// Implement an associator yourself, or use Associator.
func (r *AssocRequest) Accept(addr string) {
}

// Denies the request with REP byte code.
func (r *AssocRequest) Deny(rep byte) {
}

type Association struct{}

// Accepts the handshake.
// Handshake will be denied if:
// 1. Param neg is nil and selected method is not NO
// AUTHENTICATION.
// 2. Param method doesn't match any client's requested
// methods.
// 3. Param method is NO ACCEPTABLE METHODS
func (r *HandshakeRequest) Accept(method byte, neg Subnegotiator) {
	r.once.Do(func() {
		if neg == nil && method != MethodNoAuth || method == MethodNoAccepted {
			r.deny()
			return
		}
		for _, m := range r.methods {
			if m == method {
				r.accept(method, neg)
				return
			}
		}
		r.deny()
	})
}

func (r *HandshakeRequest) accept(method byte, neg Subnegotiator) {
	r.methodChosen = method
	r.wg.Done()
}

// Denies the handshake by returning NO ACCEPTABLE METHODS
func (r *HandshakeRequest) Deny() {
	r.once.Do(r.deny)
}

func (r *HandshakeRequest) deny() {
	r.methodChosen = MethodNoAccepted
	r.wg.Done()
}

// Client's supported auth methods. This func might return empty slice.
func (r *HandshakeRequest) Methods() []byte {
	s := make([]byte, len(r.methods))
	copy(s, r.methods)
	return s
}
