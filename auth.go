package socksy5

import (
	"errors"
	"fmt"
	"io"
	"reflect"
)

// Constants used in Username/Password Authentication for SOCKS V5 ([RFC 1929]).
//
// [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929
const (
	VerUsrPwd         byte = 0x01
	UsrPwdStatSuccess byte = 0x00
)

var ErrAuthFailed = errors.New("auth failed")

// Subnegotiator does subnegotiation after an auth method has been chosen.
//
// When subnegotiation begins, [MidLayer] will pass [net.Conn] to
// Negotiate. Implementation should retain the ReadWriter for capsulation use.
// If nil Capsulator is returned, NoCap is used instead.
// Connection is closed if non-nil error is returned.
type Subnegotiator interface {
	Negotiate(io.ReadWriter) (Capsulator, error)
	Type() string
}

// Capsulator does encapsulation and decapsulation as corresponding auth method
// requires.
type Capsulator interface {
	// Used for TCP connections.
	// MidLayer will call Write for encapsulation, and Read for decapsulation.
	// Connection is closed if non-nil error is returned.
	io.ReadWriter

	// Used for UDP packets. Packet is dropped if non-nil error is returned.
	// [MidLayer] doesn't actually call these methods,
	// Associator will call them though.
	EncapPacket(p []byte) ([]byte, error)
	DecapPacket(p []byte) ([]byte, error)
}

// A NoAuthSubneg is a [Subnegotiator] that does no negotiation at all.
// It's typically used for NO AUTHENTICATION.
type NoAuthSubneg struct{}

func (n NoAuthSubneg) Negotiate(rw io.ReadWriter) (Capsulator, error) {
	return NoCap{
		rw: rw,
	}, nil
}

// Type returns "NO AUTHENTICATION".
func (n NoAuthSubneg) Type() string {
	return "NO AUTHENTICATION"
}

// NoCap is a [Capsulator] that doesn't encapsulate/decapsulate at all.
// It's used for NO AUTHENTICATION and Username/Password Authentication.
type NoCap struct {
	rw io.ReadWriter
}

func (c NoCap) Read(p []byte) (n int, err error) {
	return c.rw.Read(p)
}

func (c NoCap) Write(p []byte) (n int, err error) {
	return c.rw.Write(p)
}

func (c NoCap) EncapPacket(p []byte) ([]byte, error) {
	q := make([]byte, len(p))
	copy(q, p)
	return q, nil
}

func (c NoCap) DecapPacket(p []byte) ([]byte, error) {
	q := make([]byte, len(p))
	copy(q, p)
	return q, nil
}

type UsrPwdVerIncorrectError byte

func (e UsrPwdVerIncorrectError) Error() string {
	return fmt.Sprintf("VER incorrect (0x%02X)", byte(e))
}

// Is returns true if target is [ErrMalformed].
func (e UsrPwdVerIncorrectError) Is(target error) bool {
	return target == ErrMalformed
}

// A UsrPwdSubneg is a [Subnegotiator] for Username/Password Authentication.
// Implements RFC 1929.
//
// [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929
type UsrPwdSubneg struct {
	// List of username password pair.
	// A list entry is to be ignored if its number of elements is not 2.
	List [][][]byte
}

func (n UsrPwdSubneg) Negotiate(rw io.ReadWriter) (c Capsulator, err error) {
	var ver byte
	ver, err = readByte(rw)
	if err != nil {
		return nil, err
	}
	if ver != VerUsrPwd {
		return nil, UsrPwdVerIncorrectError(ver)
	}

	var ulen, plen byte
	var uname, passwd []byte

	if ulen, err = readByte(rw); err != nil {
		return nil, err
	}
	uname = make([]byte, ulen)
	if _, err := io.ReadFull(rw, uname); err != nil {
		return nil, err
	}

	if plen, err = readByte(rw); err != nil {
		return nil, err
	}
	passwd = make([]byte, plen)
	if _, err := io.ReadFull(rw, passwd); err != nil {
		return nil, err
	}

	reply := []byte{VerUsrPwd, 0x01}
	for _, pair := range n.List {
		if len(pair) != 2 {
			continue
		}
		if reflect.DeepEqual(uname, pair[0]) && reflect.DeepEqual(passwd, pair[1]) {
			reply[1] = UsrPwdStatSuccess
			break
		}
	}

	if _, err = rw.Write(reply); err != nil {
		return nil, err
	}
	if reply[1] != UsrPwdStatSuccess {
		return nil, ErrAuthFailed
	}
	return NoCap{}, nil
}

// Type returns "USERNAME/PASSWORD".
func (n UsrPwdSubneg) Type() string {
	return "USERNAME/PASSWORD"
}
