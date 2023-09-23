package socksy5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strconv"
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

// An AddrPort stands for the address and the port
// sent in SOCKS5 requests and replies.
type AddrPort struct {
	// ATYP byte value
	Type byte

	// Raw bytes, port not included.
	// If ATYP is ATYPDOMAIN,
	// the first byte that specifies the FQDN length is omitted.
	Bytes []byte
	Port  uint16

	// One of "tcp" and "udp", just for convenience
	Protocol string
}

var emptyAddr = &AddrPort{Type: ATYPDOMAIN, Bytes: nil, Port: 0}

func readAddrPort(reader io.Reader) (*AddrPort, error) {
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
	if _, err := fillBuffer(content, reader); err != nil {
		return nil, err
	}
	port, err := readUInt16BigEndian(reader)
	if err != nil {
		return nil, err
	}
	return &AddrPort{
		Type:  atyp,
		Bytes: content,
		Port:  port,
	}, nil
}

func ParseAddrPort(s string) (*AddrPort, error) {
	a := new(AddrPort)
	ipPort, err := netip.ParseAddrPort(s)

	if err != nil {
		host, portS, err := net.SplitHostPort(s)
		if err != nil {
			return nil, err
		}
		port, ok := parseUint16(portS)
		if !ok {
			return nil, errors.New(portS + " is not port")
		}

		a.Type = ATYPDOMAIN
		a.Bytes = []byte(host)
		a.Port = uint16(port)
		return a, nil
	}

	ip := ipPort.Addr()
	if ip.Is4() {
		a.Type = ATYPV4
	} else {
		a.Type = ATYPV6
	}
	a.Bytes, _ = ip.MarshalBinary()
	a.Port = ipPort.Port()
	return a, nil
}

func (a *AddrPort) Network() string {
	if a == nil {
		return "<nil>"
	}
	switch a.Type {
	case ATYPV4:
		return a.Protocol + "4"
	case ATYPV6:
		return a.Protocol + "6"
	case ATYPDOMAIN:
		return a.Protocol
	}
	return fmt.Sprintf("0x%02X", a.Type)
}

func (a *AddrPort) String() string {
	if a == nil {
		return "<nil>"
	}
	var host string
	if a.Type == ATYPV4 || a.Type == ATYPV6 {
		if ip, ok := netip.AddrFromSlice(a.Bytes); ok {
			return netip.AddrPortFrom(ip, a.Port).String()
		}
		host = net.IP(a.Bytes).String()
	} else if a.Type == ATYPDOMAIN {
		host = string(a.Bytes)
	} else {
		host = fmt.Sprintf("%02X", a.Bytes)
	}
	return host + ":" + strconv.Itoa(int(a.Port))
}

// Equal tests whether a and x are the same address.
// Both a.Protocol and x.Protocol are not compared.
func (a *AddrPort) Equal(x *AddrPort) bool {
	if a == x {
		return true
	}

	return a.Type == x.Type && reflect.DeepEqual(a.Bytes, x.Bytes)
}

func (a *AddrPort) cpy() *AddrPort {
	b := new(AddrPort)
	b.Type = a.Type
	b.Bytes = make([]byte, len(a.Bytes))
	copy(b.Bytes, a.Bytes)
	b.Port = a.Port
	b.Protocol = a.Protocol
	return b
}

// MarshalBinary returns raw bytes used in SOCKS5 traffic. (ATYP+ADDR+PORT)
func (a *AddrPort) MarshalBinary() (data []byte, err error) {
	var l int

	if a.Type == ATYPDOMAIN {
		if len(a.Bytes) > 0xFF {
			return nil, ErrMalformed
		}
		l = 1 + 1 + len(a.Bytes) + 2
		data = make([]byte, l)
		data[1] = byte(l - 4)
		copy(data[2:], a.Bytes)
	} else if a.Type == ATYPV4 || a.Type == ATYPV6 {
		if a.Type == ATYPV4 && len(a.Bytes) != 4 || a.Type == ATYPV6 && len(a.Bytes) != 16 {
			return nil, ErrMalformed
		}
		l = 1 + len(a.Bytes) + 2
		data = make([]byte, l)
		copy(data[1:], a.Bytes)
	} else {
		return nil, ErrMalformed
	}

	data[0] = a.Type
	binary.BigEndian.PutUint16(data[l-2:], a.Port)
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

	wg          *sync.WaitGroup
	once        *sync.Once
	neg         Subnegotiator
	timeoutDeny bool
}

func readHandshake(reader io.Reader) (*Handshake, error) {
	hs := &Handshake{
		wg:   new(sync.WaitGroup),
		once: new(sync.Once),
	}
	var err error
	hs.ver, err = readByte(reader)
	if err != nil {
		return nil, err
	}
	if hs.ver != VerSOCKS5 {
		return nil, ErrMalformed
	}
	hs.nmethods, err = readByte(reader)
	if err != nil {
		return nil, err
	}
	hs.methods = make([]byte, hs.nmethods)
	_, err = fillBuffer(hs.methods, reader)
	if err != nil {
		return nil, err
	}
	return hs, nil
}

// Accept accepts the handshake, but also instead denies the request silently
// if params are invalid, e.g. when method is MethodNoAccepted.
//
// Can be called only once, furthur calls are no-op.
func (r *Handshake) Accept(method byte, neg Subnegotiator) (ok bool) {
	if neg == nil || method == MethodNoAccepted {
		r.deny(false)
		return
	}
	if isByteOneOf(method, r.methods...) {
		return r.accept(method, neg)
	}
	r.deny(false)
	return
}

func (r *Handshake) accept(method byte, neg Subnegotiator) (ok bool) {
	r.once.Do(func() {
		r.methodChosen = method
		r.neg = neg
		r.wg.Done()
		ok = true
	})
	return
}

// Deny denies the handshake by returning NO ACCEPTABLE METHODS.
//
// Can be called only once, furthur calls are no-op.
func (r *Handshake) Deny() (ok bool) {
	return r.deny(false)
}

func (r *Handshake) deny(timeoutDeny bool) (ok bool) {
	r.once.Do(func() {
		r.methodChosen = MethodNoAccepted
		r.timeoutDeny = timeoutDeny
		r.wg.Done()
		ok = true
	})
	return
}

// Methods returns client's supported auth methods.
// Methods might return no method,
// or include method code 0xFF if the client did send so.
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
// calls are no-op and return ok with false.
//
// Requests are denied silently if params passed to Accept funcs are invalid, e.g.
// addr string doesn't contain a port number, net.Addr returned by conn is invalid.
//
// A Request will be denied automatically if it's not accepted or denied
// after [PeriodAutoDeny].
type Request struct {
	cmd byte
	dst *AddrPort

	raddr       net.Addr
	laddr       net.Addr
	once        *sync.Once
	wg          *sync.WaitGroup
	reply       *reply
	timeoutDeny bool
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

	req.dst, err = readAddrPort(reader)
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

// Dst returns the DST fields in the request message.
func (r *Request) Dst() *AddrPort {
	return r.dst.cpy()
}

// Deny denies the request with REP byte code.
// If rep is RepSucceeded, it's replaced by RepGeneralFailure.
//
// addr is used for BND fields. If addr is invalid, BND.ADDR
// will be set to empty domain name, and BND.PORT set to 0.
func (r *Request) Deny(rep byte, addr string) (ok bool) {
	a, err := ParseAddrPort(addr)

	if err != nil {
		return r.deny(rep, emptyAddr, false)
	}
	return r.deny(rep, a, false)
}

func (r *Request) deny(rep byte, addr *AddrPort, timeoutDeny bool) (ok bool) {
	r.once.Do(func() {
		if rep == RepSucceeded {
			r.reply.rep = RepGeneralFailure
		} else {
			r.reply.rep = rep
		}
		r.reply.addr = addr
		r.timeoutDeny = timeoutDeny
		r.wg.Done()
		ok = true
	})
	return
}

type ConnectRequest struct {
	Request
	conn net.Conn
}

// Accept accepts the request, and starts proxying.
// Port 0 is valid and will be sent as-is.
func (r *ConnectRequest) Accept(conn net.Conn) (ok bool) {
	if conn == nil || conn.LocalAddr() == nil {
		r.deny(RepGeneralFailure, emptyAddr.cpy(), false)
		return
	}
	addr, err := ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		r.deny(RepGeneralFailure, emptyAddr, false)
		return
	}
	return r.accept(conn, addr)
}

func (r *ConnectRequest) accept(conn net.Conn, addr *AddrPort) (ok bool) {
	r.once.Do(func() {
		r.conn = conn
		r.reply.addr = addr
		r.wg.Done()
		ok = true
	})
	return
}

type BindRequest struct {
	Request
	conn            net.Conn
	bindMux         sync.Mutex // To avoid simultainous rw on reply field, Bind uses it to check if the request is accepted.
	bindWg          sync.WaitGroup
	bindOnce        sync.Once
	bindReply       *reply
	bindTimeoutDeny bool
}

// Accept accepts the request, and tells the client which address the SOCKS server
// will listen on. This is the first reply from the server.
//
// Note that [Server] doesn't actually listens it for you. You can implement a
// listener yourself or use Binder.
// Port 0 is valid and will be sent as-is.
func (r *BindRequest) Accept(addr string) (ok bool) {
	a, err := ParseAddrPort(addr)
	if err != nil {
		r.deny(RepGeneralFailure, emptyAddr, false)
		return
	}
	return r.accept(a)
}

func (r *BindRequest) accept(addr *AddrPort) (ok bool) {
	r.once.Do(func() {
		r.bindMux.Lock()
		defer r.bindMux.Unlock()
		r.reply = new(reply)
		r.reply.addr = addr
		r.wg.Done()
		ok = true
	})
	return
}

// Bind binds the client. This is the second reply from the server.
//
// No-op if the first reply is not decided.
// Request is denied if conn is nil.
// Port 0 is valid and will be sent as-is.
func (r *BindRequest) Bind(conn net.Conn) (ok bool) {
	r.bindMux.Lock()
	defer r.bindMux.Unlock()
	if r.reply == nil {
		return
	}

	if conn == nil || conn.LocalAddr() == nil {
		r.denyBind(RepGeneralFailure, emptyAddr, false)
		return
	}
	addr, err := ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		r.denyBind(RepGeneralFailure, emptyAddr, false)
		return
	}
	return r.bind(conn, addr)
}

func (r *BindRequest) bind(conn net.Conn, addr *AddrPort) (ok bool) {
	r.bindOnce.Do(func() {
		r.conn = conn
		r.bindReply = new(reply)
		r.bindReply.addr = addr
		ok = true
	})
	return
}

// DenyBind denies the request.
// No-op if the first reply is not decided.
func (r *BindRequest) DenyBind(rep byte, addr string) (ok bool) {
	r.bindMux.Lock()
	defer r.bindMux.Unlock()
	if r.reply == nil {
		return
	}

	a, err := ParseAddrPort(addr)
	if err != nil {
		r.deny(rep, emptyAddr, false)
	} else {
		ok = r.deny(rep, a, false)
	}
	return
}

func (r *BindRequest) denyBind(rep byte, addr *AddrPort, timeoutDeny bool) (ok bool) {
	r.bindOnce.Do(func() {
		if rep == RepSucceeded {
			r.bindReply.rep = RepGeneralFailure
		} else {
			r.bindReply.rep = rep
		}
		r.bindReply = new(reply)
		r.bindReply.addr = addr
		r.bindTimeoutDeny = timeoutDeny
		r.bindWg.Done()
		ok = true
	})
	return
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
	a, err := ParseAddrPort(addr)
	if err != nil {
		r.deny(RepGeneralFailure, emptyAddr, false)
		return nil
	}
	return r.accept(a, notify)
}

func (r *AssocRequest) accept(addr *AddrPort, notify func(error)) (terminator func() error) {
	var t func() error
	r.once.Do(func() {
		r.notify = notify

		t = r.terminate

		r.wg.Done()
	})
	return t
}

type reply struct {
	rep  byte
	addr *AddrPort
}

func (r *reply) MarshalBinary() (data []byte, err error) {
	aBytes, _ := r.addr.MarshalBinary()
	l := 1 + 1 + 1 + len(aBytes)
	data = make([]byte, l)
	data[0] = VerSOCKS5
	data[1] = r.rep
	data[2] = RSV
	copy(data[3:], aBytes)
	return data, nil
}
