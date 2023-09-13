package socksy5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/asaskevich/govalidator"
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

// CMD codes.
const (
	CmdCONNECT byte = 0x01
	CmdBIND    byte = 0x02
	CmdASSOC   byte = 0x03
)

const RSV byte = 0x00 // Value of reserved bytes

// ATYP codes (address types).
const (
	ATYPV4     byte = 0x01 // IPv4
	ATYPDOMAIN byte = 0x03 // Fully-qualified domain name
	ATYPV6     byte = 0x04 // IPv6
)

// REP reply codes.
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

// An Addr stands for addresses sent in SOCKS5 requests and replies.
//
// Does not include port.
type Addr struct {
	Type byte // ATYP byte value

	// Raw bytes, if ATYP is ATYPDOMAIN, the first byte that specifies the FQDN length
	// is omitted.
	Bytes []byte
}

var emptyFQDN = &Addr{Type: ATYPDOMAIN, Bytes: nil}

const zeroPort uint16 = 0x0000

func readAddr(reader io.Reader) (*Addr, error) {
	atyp, err := readByte(reader)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		content = make([]byte, l)
	default:
		return nil, ErrMalformed
	}
	_, err = fillBuffer(content, reader)
	if err != nil {
		return nil, err
	}
	return &Addr{
		Type:  atyp,
		Bytes: content,
	}, nil
}

func parseHost(host string) *Addr {
	ip := net.ParseIP(host)
	a := new(Addr)
	if ip == nil {
		a.Type = ATYPDOMAIN
		a.Bytes = []byte(host)
		return a
	}
	if govalidator.IsIPv4(host) {
		a.Type = ATYPV4
		a.Bytes = ip.To4()
		return a
	}
	a.Type = ATYPV6
	a.Bytes = ip.To16()
	return a
}

func parseHostPort(addr string) (*Addr, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0
	}
	port, ok := parseUint16(portStr)
	if !ok {
		return nil, 0
	}
	return parseHost(host), port
}

// Network returns "ip4" if ATYP byte value is ATYPV4, "ip6" if ATYPV6,
// "ip" if ATYPDOMAIN,
// "unknown" otherwise, 
// though [Server] will consider it malformed if the received ATYP is not one of 
// the three known address types. 
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
	return fmt.Sprintf("% X", a.Bytes)
}

func (a *Addr) cpy() *Addr {
	b := new(Addr)
	b.Type = a.Type
	b.Bytes = make([]byte, len(a.Bytes))
	copy(b.Bytes, a.Bytes)
	return b
}

// MarshalBinary returns raw bytes used in SOCKS5 traffic. (ATYP+ADDR)
//
// Always returns nil error.
func (a *Addr) MarshalBinary() (data []byte, err error) {
	if a.Type == ATYPDOMAIN {
		var l int
		if len(data) > 0xFF {
			l = 0xFF
		} else {
			l = len(data)
		}
		data = make([]byte, 2+l)
		data[1] = byte(l)
		copy(data[2:], a.Bytes)
	} else {
		data = make([]byte, 1+len(a.Bytes))
		copy(data[1:], a.Bytes)
	}
	data[0] = a.Type
	return
}

// A Handshake represents the handshake message the client sends after connecting to
// the server.
// Handshake will be denied automatically if it's not accepted or denied
// after [PeriodAutoDeny].
type Handshake struct {
	ver          byte
	nmethods     byte
	methods      []byte
	methodChosen byte
	laddr        net.Addr
	raddr        net.Addr

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

// Accept accepts the handshake, but also instead denies the request silently
// if params are invalid, e.g. when method is MethodNoAccepted.
//
// Can be called only once, furthur calls are no-op.
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

// Deny denies the handshake by returning NO ACCEPTABLE METHODS.
// 
// Can be called only once, furthur calls are no-op.
func (r *Handshake) Deny() {
	r.deny()
}

func (r *Handshake) deny() {
	r.once.Do(func() {
		r.methodChosen = MethodNoAccepted
		r.wg.Done()
	})
}

// Methods returns client's supported auth methods. 
// Methods might return no method.
func (r *Handshake) Methods() []byte {
	s := make([]byte, len(r.methods))
	copy(s, r.methods)
	return s
}

func (r *Handshake) LocalAddr() net.Addr {
	return r.laddr
}

func (r *Handshake) RemoteAddr() net.Addr {
	return r.raddr
}

// A Request represents a client request. 
// Use [ConnectRequest] e.t.c. for manipulation.
// 
// All different types of requests can be accepted / denied only once. Furthur
// calls are no-op. 
// 
// Requests are denied silently if params passed to Accept funcs are invalid, e.g.
// addr string doesn't contain a port number, net.Addr returned by conn is invalid.
// 
// A Request will be denied automatically if it's not accepted or denied
// after [PeriodAutoDeny].
type Request struct {
	cmd     byte
	dstAddr *Addr
	dstPort uint16 // Native byte order

	raddr net.Addr
	laddr net.Addr
	once  *sync.Once
	wg    *sync.WaitGroup
	reply *reply
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

	req.once = new(sync.Once)
	req.wg = new(sync.WaitGroup)
	req.reply = new(reply)

	return req, nil
}

func (r *Request) LocalAddr() net.Addr {
	return r.laddr
}

func (r *Request) RemoteAddr() net.Addr {
	return r.raddr
}

// DstAddr returns the DST.ADDR field in the request message. 
func (r *Request) DstAddr() *Addr {
	return r.dstAddr.cpy()
}

// DstAddr returns the DST.PORT field in the request message. 
func (r *Request) DstPort() uint16 {
	return r.dstPort
}

// Deny denies the request with REP byte code.
// If rep is RepSucceeded, it's replaced by RepGeneralFailure.
// 
// addr is used for BND fields. If addr is invalid, BND.ADDR
// will be set to empty domain name, and BND.PORT set to 0.
func (r *Request) Deny(rep byte, addr string) {
	a, port := parseHostPort(addr)
	if a == nil {
		r.deny(rep, emptyFQDN, zeroPort)
		return
	}
	r.deny(rep, a, port)
}

func (r *Request) deny(rep byte, addr *Addr, port uint16) {
	r.once.Do(func() {
		if rep == RepSucceeded {
			r.reply.rep = RepGeneralFailure
		} else {
			r.reply.rep = rep
		}
		r.reply.bndAddr = addr
		r.reply.bndPort = port
		r.wg.Done()
	})
}

type ConnectRequest struct {
	Request
	conn net.Conn
}

// Accept accepts the request, and starts proxying.
// Port 0 is valid and will be sent as-is.
func (r *ConnectRequest) Accept(conn net.Conn) {
	if conn == nil || conn.LocalAddr() == nil {
		r.deny(RepGeneralFailure, emptyFQDN.cpy(), zeroPort)
		return
	}
	addr, port := parseHostPort(conn.LocalAddr().String())
	if addr == nil {
		r.deny(RepGeneralFailure, emptyFQDN, zeroPort)
		return
	}
	r.accept(conn, addr, port)
}

func (r *ConnectRequest) accept(conn net.Conn, addr *Addr, port uint16) {
	r.once.Do(func() {
		r.conn = conn
		r.reply.bndAddr = addr
		r.reply.bndPort = port
		r.wg.Done()
	})
}

type BindRequest struct {
	Request
	conn      net.Conn
	bindMux   sync.Mutex // To avoid simultainous rw on reply field, Bind uses it to check if the request is accepted. 
	bindWg    sync.WaitGroup
	bindOnce  sync.Once
	bindReply *reply
}

// Accept accepts the request, and tells the client which address the SOCKS server
// will listen on. This is the first reply from the server.
// 
// Note that [Server] doesn't actually listens it for you. You can implement a
// listener yourself or use Binder.
// Port 0 is valid and will be sent as-is.
func (r *BindRequest) Accept(addr string) {
	a, port := parseHostPort(addr)
	if a == nil {
		r.deny(RepGeneralFailure, emptyFQDN, zeroPort)
		return
	}
	r.accept(a, port)
}

func (r *BindRequest) accept(addr *Addr, port uint16) {
	r.once.Do(func() {
		r.bindMux.Lock()
		defer r.bindMux.Unlock()
		r.reply = new(reply)
		r.reply.bndAddr = addr
		r.reply.bndPort = port
		r.wg.Done()
	})
}

// Bind binds the client. This is the second reply from the server.
// 
// No-op if the first reply is not decided.
// Request is denied if conn is nil.
// Port 0 is valid and will be sent as-is.
func (r *BindRequest) Bind(conn net.Conn) {
	r.bindMux.Lock()
	defer r.bindMux.Unlock()
	if r.reply == nil {
		return
	}

	if conn == nil || conn.LocalAddr() == nil {
		r.denyBind(RepGeneralFailure, emptyFQDN, zeroPort)
		return
	}
	addr, port := parseHostPort(conn.LocalAddr().String())
	if addr == nil {
		r.denyBind(RepGeneralFailure, emptyFQDN, zeroPort)
		return
	}
	r.bind(conn, addr, port)
}

func (r *BindRequest) bind(conn net.Conn, addr *Addr, port uint16) {
	r.bindOnce.Do(func() {
		r.conn = conn
		r.bindReply = new(reply)
		r.bindReply.bndAddr = addr
		r.bindReply.bndPort = port
	})
}

// DenyBind denies the request. 
// No-op if the first reply is not decided.
func (r *BindRequest) DenyBind(rep byte, addr string) {
	r.bindMux.Lock()
	defer r.bindMux.Unlock()
	if r.reply == nil {
		return
	}

	a, port := parseHostPort(addr)
	if a == nil {
		r.deny(rep, emptyFQDN, zeroPort)
	} else {
		r.deny(rep, a, port)
	}
}

func (r *BindRequest) denyBind(rep byte, addr *Addr, port uint16) {
	r.bindOnce.Do(func() {
		if rep == RepSucceeded {
			r.bindReply.rep = RepGeneralFailure
		} else {
			r.bindReply.rep = rep
		}
		r.bindReply = new(reply)
		r.bindReply.bndAddr = addr
		r.bindReply.bndPort = port
	})
}

type AssocRequest struct {
	Request
	notifyOnce sync.Once
	notify     func(error)
	terminate  func() error
}

// Accept accepts the request. 
// 
// notify is called when the association terminates, e.g. TCP disconnection,
// IO error. 
//
// terminator can be used to terminate the association by closing the control 
// connection. Be aware it is nil if Accept is no-op. 
// 
// Note that [Server] doesn't actually relays the UDP traffic.
// Implement an associator yourself, or use [Associator].
// 
// Port 0 is valid and will be sent as-is.
func (r *AssocRequest) Accept(addr string, notify func(reason error)) (terminator func() error) {
	a, port := parseHostPort(addr)
	if a == nil {
		r.deny(RepGeneralFailure, emptyFQDN, zeroPort)
		return nil
	}
	return r.accept(a, port, notify)
}

func (r *AssocRequest) accept(addr *Addr, port uint16, notify func(error)) (terminator func() error) {
  var t func() error
	r.once.Do(func() {
		r.notify = notify

		t = r.terminate

		r.wg.Done()
	})
	return t
}

type reply struct {
	rep     byte
	bndAddr *Addr
	bndPort uint16
}

func (r *reply) MarshalBinary() (data []byte, err error) {
	aBytes, _ := r.bndAddr.MarshalBinary()
	l := 1 + 1 + 1 + len(aBytes) + 2
	data = make([]byte, l)
	data[0] = VerSOCKS5
	data[1] = r.rep
	data[2] = RSV
	copy(data[2:], aBytes)
	binary.BigEndian.PutUint16(data[l-2:], r.bndPort)
	return data, nil
}
