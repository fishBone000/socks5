package s5i

import (
	"io"
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

type addr struct {
	atyp    byte
	content []byte
}

func readAddr(reader io.Reader) (addr, error) {
	atyp, err := readByte(reader)
	if err != nil {
		return addr{}, err
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
			return addr{}, err
		}
		content = make([]byte, 1+l)
	default:
		return addr{}, ErrMalformed
	}
	if atyp == ATYPDOMAIN {
		_, err = fillBuffer(content[1:], reader)
	} else {
		_, err = fillBuffer(content, reader)
	}
	if err != nil {
		return addr{}, err
	}
	return addr{
		atyp:    atyp,
		content: content,
	}, nil
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

type request struct {
	cmd     byte
	dstAddr addr
	dstPort uint16 // Native byte order
}

func readRequest(reader io.Reader) (request, error) {
  ver, err := readByte(reader)
  if err != nil {
    return request{}, err
  }
  if ver != VerSOCKS5 {
    return request{}, ErrMalformed
  }

  req := request{}
  req.cmd, err = readByte(reader)
  if err != nil {
    return request{}, err
  }

  rsv, err := readByte(reader)
  if err != nil {
    return request{}, err
  }
  if rsv != RSV {
    return request{}, ErrMalformed
  }

  req.dstAddr, err = readAddr(reader)
  if err != nil {
    return request{}, err
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
