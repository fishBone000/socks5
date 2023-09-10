package s5i

import "io"

const VerSOCKS5 byte = 0x05 // SOCKS5 VER byte

// Authentication METHOD codes, for now only NO AUTHENTICATION is supported
const (
	MethodNoAuth     byte = 0x00
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

type handshakeRequest struct {
	ver      byte
	nmethods byte
	methods  []byte
	authCtx  interface{} // Contains auth method specific context, e.g. usr/pwd, not used for now

	s *Server
}

func readHandshakeRequest(reader io.Reader) (handshakeRequest, error) {
	req := handshakeRequest{}
	var err error
	req.ver, err = readByte(reader)
	if err != nil {
		return handshakeRequest{}, err
	}
	if req.ver != VerSOCKS5 {
		return handshakeRequest{}, ErrMalformed
	}
	req.nmethods, err = readByte(reader)
	if err != nil {
		return handshakeRequest{}, err
	}
	req.methods = make([]byte, req.nmethods)
	_, err = fillBuffer(req.methods, reader)
	if err != nil {
		return handshakeRequest{}, err
	}
	return req, nil
}

func (r *handshakeRequest) Accept() {
}

func (r *handshakeRequest) Deny() {
}
