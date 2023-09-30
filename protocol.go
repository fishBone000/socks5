package socksy5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"sync"

	"github.com/google/uuid"
)

// SOCKS5 VER byte
const VerSOCKS5 byte = 0x05 

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

// Value of reserved bytes
const RSV byte = 0x00 

// ATYP codes (address types)
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

// An AddrPort represents the address and the port
// sent in SOCKS5 requests and replies.
type AddrPort struct {
	// ATYP byte value
	Type byte

	// If ATYP is ATYPDOMAIN,
	// the first byte that specifies the FQDN length is omitted,
	// length of Addr represents it implicitly.
	Addr []byte
	Port uint16

	// One of "tcp" and "udp", [AddrPort.Network] relies on this field. 
	Protocol string
}

var emptyAddr = &AddrPort{Type: ATYPDOMAIN, Addr: nil, Port: 0}

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
		return nil, ATYPNotSupportedError(atyp)
	}
	if _, err := io.ReadFull(reader, content); err != nil {
		return nil, err
	}
	port, err := readUInt16BigEndian(reader)
	if err != nil {
		return nil, err
	}
	return &AddrPort{
		Type: atyp,
		Addr: content,
		Port: port,
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
		port, err := parseUint16(portS)
		if err != nil {
			return nil, err
		}

		a.Type = ATYPDOMAIN
		a.Addr = []byte(host)
		a.Port = uint16(port)
		return a, nil
	}

	ip := ipPort.Addr()
	if ip.Is4() {
		a.Type = ATYPV4
	} else {
		a.Type = ATYPV6
	}
	a.Addr, _ = ip.MarshalBinary()
	a.Port = ipPort.Port()
	return a, nil
}

// Network returns the network of a.
// If a.Type is one of [ATYPV4] or [ATYPV6],
// Network will append "4" or "6" to a.Protocol accordingly.
// If a.Type is [ATYPDOMAIN], Network will just return a.Protocol.
// Otherwise, Network returns the hex of a.Type.
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
	host := a.Host()
	portStr := strconv.Itoa(int(a.Port))
	return net.JoinHostPort(host, portStr)
}

func (a *AddrPort) Host() string {
	if a == nil {
		return "<nil>"
	}
	if a.Type == ATYPV4 || a.Type == ATYPV6 {
		return net.IP(a.Addr).String()
	}
	if a.Type == ATYPDOMAIN {
		return string(a.Addr)
	}
	return fmt.Sprintf("%02X", a.Addr)
}

// Equal tests whether a and x are the same address,
// returns false if either a or x is nil.
// Both a.Protocol and x.Protocol are ignored.
func (a *AddrPort) Equal(x *AddrPort) bool {
	if a == nil || x == nil {
		return false
	}
	if a == x {
		return true
	}

	return a.Type == x.Type && reflect.DeepEqual(a.Addr, x.Addr) && a.Port == x.Port
}

func (a *AddrPort) cpy() *AddrPort {
	b := new(AddrPort)
	b.Type = a.Type
	b.Addr = make([]byte, len(a.Addr))
	copy(b.Addr, a.Addr)
	b.Port = a.Port
	b.Protocol = a.Protocol
	return b
}

// MarshalBinary returns raw bytes used in SOCKS5 traffic. (ATYP+ADDR+PORT)
func (a *AddrPort) MarshalBinary() (data []byte, err error) {
	var l int

	if a.Type == ATYPDOMAIN {
		if len(a.Addr) > 0xFF {
			return nil, fmt.Errorf("%w: domain name length too long (%d Bytes)", ErrMalformed, len(a.Addr))
		}
		l = 1 + 1 + len(a.Addr) + 2
		data = make([]byte, l)
		data[1] = byte(l - 4)
		copy(data[2:], a.Addr)
	} else if a.Type == ATYPV4 || a.Type == ATYPV6 {
		if a.Type == ATYPV4 && len(a.Addr) != 4 || a.Type == ATYPV6 && len(a.Addr) != 16 {
			return nil, fmt.Errorf("%w: address length incorrect (%d Bytes)", ErrMalformed, len(a.Addr))
		}
		l = 1 + len(a.Addr) + 2
		data = make([]byte, l)
		copy(data[1:], a.Addr)
	} else {
		return nil, ATYPNotSupportedError(a.Type)
	}

	data[0] = a.Type
	binary.BigEndian.PutUint16(data[l-2:], a.Port)
	return
}

// A Handshake represents the version identifier/method selection message.
// The message is called handshake in this entire module because...its full name
// is just too long.
// Handshake will be denied automatically if it's not accepted or denied
// after [PeriodAutoDeny].
type Handshake struct {
	ver          byte
	nmethods     byte
	methods      []byte
	methodChosen byte
	laddr        net.Addr
	raddr        net.Addr
	uuid         uuid.UUID

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
		return nil, VerIncorrectError(hs.ver)
	}
	hs.nmethods, err = readByte(reader)
	if err != nil {
		return nil, err
	}
	hs.methods = make([]byte, hs.nmethods)
	_, err = io.ReadFull(reader, hs.methods)
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

// UUID returns the UUID of the session of hs.
// As soon as the [MidLayer] read the handshake message, the connection is
// considered as a valid session and is bound with a UUID.
// You can use the UUID to tell which handshake and which request belongs to
// which connection.
func (hs *Handshake) UUID() uuid.UUID {
	return hs.uuid
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

	capper Capsulator
	uuid   uuid.UUID

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
		return nil, VerIncorrectError(ver)
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
		return nil, RsvViolationError(rsv)
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
			r.reply.code = RepGeneralFailure
		} else {
			r.reply.code = rep
		}
		r.reply.addr = addr
		r.timeoutDeny = timeoutDeny
		r.wg.Done()
		ok = true
	})
	return
}

// Capsulation returns the [Capsulator] in use.
func (r *Request) Capsulation() Capsulator {
	return r.capper
}

// UUID returns the UUID of the session of r.
// As soon as the [MidLayer] read the handshake message, the connection is
// considered as a valid session and is bound with a UUID.
// You can use the UUID to tell which handshake and which request belongs to
// which connection.
func (r *Request) UUID() uuid.UUID {
	return r.uuid
}

type ConnectRequest struct {
	Request
	outbound net.Conn
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
		r.outbound = conn
		r.reply.addr = addr
		r.wg.Done()
		ok = true
	})
	return
}

type BindRequest struct {
	Request
	hostConn  net.Conn
	bindMux   sync.Mutex // To avoid simultainous rw on reply field, Bind uses it to check if the request is accepted.
	bindWg    sync.WaitGroup
	bindOnce  sync.Once
	bindReply *reply
}

// Accept accepts the request, and tells the client which address the SOCKS server
// will listen on. This is the first reply from the server.
//
// Note that [MidLayer] doesn't actually listens it for you. You can implement a
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
		r.hostConn = conn
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
			r.bindReply.code = RepGeneralFailure
		} else {
			r.bindReply.code = rep
		}
		r.bindReply = new(reply)
		r.bindReply.addr = addr
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
	finalErr   error
}

// Accept accepts the request.
//
// terminate can be used to terminate the association by closing the control
// connection. Be aware it is nil if ok is false.
//
// notify is called when the association terminates, e.g. TCP disconnection,
// IO error, call on terminate.
// If client closed the control connection, reason will be [io.EOF].
// If terminate is called, reason will be nil.
// Otherwise, reason will be read error on the control connection.
// notify will only be called once, if it's not nil.
//
// Note that [MidLayer] doesn't actually relays the UDP traffic.
// Implement a relay yourself, or use [Associator].
//
// Port 0 is valid and will be sent as-is.
func (r *AssocRequest) Accept(addr string, notify func(reason error)) (terminate func() error, ok bool) {
	a, err := ParseAddrPort(addr)
	if err != nil {
		r.deny(RepGeneralFailure, emptyAddr, false)
		return nil, false
	}
	return r.accept(a, notify)
}

func (r *AssocRequest) accept(addr *AddrPort, notify func(error)) (terminate func() error, ok bool) {
	r.once.Do(func() {
		r.notify = notify

		terminate = r.terminate

		ok = true
		r.wg.Done()
	})
	return
}

type reply struct {
	code  byte
	addr *AddrPort
}

// Guarantees to return nil error.
func (r *reply) MarshalBinary() (data []byte, err error) {
	aBytes, _ := r.addr.MarshalBinary()
	l := 1 + 1 + 1 + len(aBytes)
	data = make([]byte, l)
	data[0] = VerSOCKS5
	data[1] = r.code
	data[2] = RSV
	copy(data[3:], aBytes)
	return data, nil
}

type udpPacket struct {
	frag byte
	dst  *AddrPort
	data []byte
}

func (p *udpPacket) UnmarshalBinary(data []byte) error {
  // We use ErrMalformed here instead of specific err type, because 
  // the packet will be dropped by Associator silently. 
	if len(data) < 3 {
		return ErrMalformed
	}
	if data[0] != RSV || data[1] != RSV {
		return ErrMalformed
	}

	r := &sliceReader{
		bytes: data[3:],
	}
	dst, err := readAddrPort(r)
	if err != nil {
		if err == io.EOF {
			err = ErrMalformed
		}
		return err
	}
	dst.Protocol = "udp"
	p.dst = dst

	p.data = cpySlice(data[3+r.n:])
	p.frag = data[2]
	return nil
}

func (p *udpPacket) MarshalBinary() ([]byte, error) {
	addrRaw, err := p.dst.MarshalBinary()
	if err != nil {
		return nil, err
	}
	result := make([]byte, 3+len(addrRaw)+len(p.data))
	result[2] = p.frag
	copy(result[3:], addrRaw)
	copy(result[3+len(addrRaw):], p.data)
	return result, nil
}
