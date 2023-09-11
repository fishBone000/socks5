package s5i

import (
	"fmt"
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
	Type byte // ATYP byte value

	// Raw bytes, if ATYP is ATYPDOMAIN, the first byte that specifies the FQDN length
	// is omitted.
	Bytes []byte
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
		content = make([]byte, l)
	default:
		return &Addr{}, ErrMalformed
	}
	_, err = fillBuffer(content, reader)
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
	if a.Type == ATYPDOMAIN {
		return string(a.Bytes)
	}
	return fmt.Sprintf("unknown network 0x%02X addr(hex) % X", a.Type, a.Bytes)
}

func (a *Addr) cpy() *Addr {
	b := new(Addr)
	b.Type = a.Type
	b.Bytes = make([]byte, len(a.Bytes))
	copy(b.Bytes, a.Bytes)
	return b
}

type Handshake struct {
	ver          byte
	nmethods     byte
	methods      []byte
	methodChosen byte

	wg   *sync.WaitGroup
	once *sync.Once
	neg  Subnegotiator
}

func readHandshake(reader io.Reader) (Handshake, error) {
	req := Handshake{
		wg:   new(sync.WaitGroup),
		once: new(sync.Once),
	}
	var err error
	req.ver, err = readByte(reader)
	if err != nil {
		return Handshake{}, err
	}
	if req.ver != VerSOCKS5 {
		return Handshake{}, ErrMalformed
	}
	req.nmethods, err = readByte(reader)
	if err != nil {
		return Handshake{}, err
	}
	req.methods = make([]byte, req.nmethods)
	_, err = fillBuffer(req.methods, reader)
	if err != nil {
		return Handshake{}, err
	}
	return req, nil
}

// Accepts the handshake.
// Handshake will be denied if:
// 1. Param neg is nil and selected method is not NO
// AUTHENTICATION.
// 2. Param method doesn't match any client's requested
// methods.
// 3. Param method is NO ACCEPTABLE METHODS
func (r *Handshake) Accept(method byte, neg Subnegotiator) {
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
}

func (r *Handshake) accept(method byte, neg Subnegotiator) {
	r.once.Do(func() {
		r.methodChosen = method
		r.wg.Done()
	})
}

// Denies the handshake by returning NO ACCEPTABLE METHODS
func (r *Handshake) Deny() {
	r.deny()
}

func (r *Handshake) deny() {
	r.once.Do(func() {
		r.methodChosen = MethodNoAccepted
		r.wg.Done()
	})
}

// Client's supported auth methods. This func might return 0 method.
func (r *Handshake) Methods() []byte {
	s := make([]byte, len(r.methods))
	copy(s, r.methods)
	return s
}

// Request contains common info of all types of requests, like CMD and DST.
// Use ConnectRequest e.t.c. for manipulation.
type Request struct {
	cmd     byte
	dstAddr *Addr
	dstPort uint16 // Native byte order

	raddr net.Addr
	laddr net.Addr
	once  *sync.Once
	wg    *sync.WaitGroup
	// Watch out, when Request is assigned to different types of
	// requests, it's copy assigned! So use Request.reply() to read
	// the rep field in Server.serveClient()!
	rep byte
}

func readRequest(reader io.Reader) (*Request, error) {
	ver, err := readByte(reader)
	if err != nil {
		return nil, err
	}
	if ver != VerSOCKS5 {
		return nil, ErrMalformed
	}

	req := new(Request)
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

func (r *Request) LocalAddr() net.Addr {
	return r.laddr
}

func (r *Request) RemoteAddr() net.Addr {
	return r.raddr
}

func (r *Request) DstAddr() *Addr {
	return r.dstAddr.cpy()
}

func (r *Request) DstPort() uint16 {
	return r.dstPort
}

// Denies the request with REP byte code.
// If rep is RepSucceeded, it's replaced by RepGeneralFailure.
func (r *Request) Deny(rep byte) {
	r.deny(rep)
}

func (r *Request) deny(rep byte) {
	r.once.Do(func() {
		if rep == RepSucceeded {
			r.rep = RepGeneralFailure
		} else {
			r.rep = rep
		}
		r.wg.Done()
	})
}

func (r *Request) reply() byte {
	return r.rep
}

type ConnectRequest struct {
	Request
	conn net.Conn
}

// Accepts the request, and starts proxying.
// Request is denied if param conn is nil.
func (r *ConnectRequest) Accept(conn net.Conn) {
	if conn != nil {
		r.accept(conn)
	} else {
		r.deny(RepGeneralFailure)
	}
}

func (r *ConnectRequest) accept(conn net.Conn) {
	r.once.Do(func() {
		r.conn = conn
		r.wg.Done()
	})
}

type BindRequest struct {
	Request
	laddr    *Addr
	conn     net.Conn
	bindWg   *sync.WaitGroup
	bindOnce *sync.Once
}

// Accepts the request, and tells the client which address the SOCKS server
// will listen on. This is the first reply from the server.
// Note that s5i doesn't actually listens it for you. You can implement a
// listener yourself or use Binder.
// Also note that if addr.Type is not one of known types, addr.Type and addr.Bytes
// will be sent AS-IS.
// Mutli-homed binding is allowed.
// Request is denied if addr is nil, or length of addr.Bytes is not 4 if IPv4, not 16 if IPv6.
func (r *BindRequest) Accept(addr *Addr) {
	if addr == nil {
		r.deny(RepGeneralFailure)
	} else {
		r.accept(addr)
	}
}

func (r *BindRequest) accept(addr *Addr) {
	r.once.Do(func() {
		r.laddr = addr
		r.wg.Done()
	})
}

// Binds the client. This is the second reply from the server.
// The server interface will pipe the conn to the client.
// RepGeneralFailure will be replied if conn is nil.
func (r *BindRequest) Bind(conn net.Conn) {
	r.bindOnce.Do(func() {
		r.conn = conn
		r.bindWg.Done()
	})
}

type AssocRequest struct {
	Request
	addr      *Addr
	onTermRef *func(error)
	terminate func() error
}

// Accepts the request.
// onTerm is called when the association terminates, e.g. TCP disconnection or IO
// error.
// Note that s5i doesn't actually relays the UDP traffic.
// Implement an associator yourself, or use Associator.
// Request is denied if addr is nil.
func (r *AssocRequest) Accept(addr *Addr, onTerm func(error)) *Association {
	if addr == nil {
		r.deny(RepGeneralFailure)
		return nil
	}
	return r.accept(addr, onTerm)
}

func (r *AssocRequest) accept(addr *Addr, onTerm func(error)) *Association {
	var a *Association
	r.once.Do(func() {
		r.addr = addr
		r.onTermRef = &onTerm
		r.wg.Done()

		a = new(Association)
		a.terminate = r.terminate
	})
	return a
}

// Association is provided for terminating the UDP association.
type Association struct {
	terminate func() error
}

// Terminates the association.
func (a *Association) Terminate() error {
	return a.terminate()
}
