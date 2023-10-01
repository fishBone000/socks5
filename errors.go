package socksy5

import (
	"errors"
	"fmt"
	"net"
)

// ErrMalformed represents protocol format violation.
// Usually a more specific error type is used:
// [VerIncorrectError], [RsvViolationError], [CmdNotSupportedError],
// [ATYPNotSupportedError] and [UsrPwdVerIncorrectErr].
var ErrMalformed = errors.New("malformed")

type VerIncorrectError byte

func (e VerIncorrectError) Error() string {
	return fmt.Sprintf("VER incorrect (0x%02X)", byte(e))
}

// Is returns true if target is [ErrMalformed].
func (e VerIncorrectError) Is(target error) bool {
	return target == ErrMalformed
}

type RsvViolationError byte

func (e RsvViolationError) Error() string {
	return fmt.Sprintf("RSV violation (0x%02X)", byte(e))
}

// Is returns true if target is [ErrMalformed].
func (e RsvViolationError) Is(target error) bool {
	return target == ErrMalformed
}

type CmdNotSupportedError byte

func (e CmdNotSupportedError) Error() string {
	return fmt.Sprintf("CMD 0x%02X not supported", byte(e))
}

// Is returns true if target is [ErrMalformed].
func (e CmdNotSupportedError) Is(target error) bool {
	return target == ErrMalformed
}

// Unwrap returns [errors.ErrUnsupported].
func (e CmdNotSupportedError) Unwrap() error {
	return errors.ErrUnsupported
}

type ATYPNotSupportedError byte

func (e ATYPNotSupportedError) Error() string {
	return fmt.Sprintf("ATYP 0x%02X not supported", byte(e))
}

// Is returns true if target is [ErrMalformed].
func (e ATYPNotSupportedError) Is(target error) bool {
	return target == ErrMalformed
}

// Unwrap returns [errors.ErrUnsupported].
func (e ATYPNotSupportedError) Unwrap() error {
	return errors.ErrUnsupported
}

// ErrAcceptOrDenyFailed is used by [Connect], [Binder] and [Associator].
// It indicates that the accept and deny methods of the request returned not ok.
var ErrAcceptOrDenyFailed = errors.New("request already handled")

// ErrDuplicatedRequest is returned by [Associator.Handle] and [Binder.Handle]
// indicating that another request with same parameters is being handled,
// e.g. the [Binder] is already listening the address stated by the BIND request.
var ErrDuplicatedRequest = errors.New("duplicated request with same parameters")

// An OpError contains Op string describing in which operation has the error occured.
// Currently the error util of socksy5 is not well designed, so OpError is for now
// just for the convenience of converting errors to strings.
type OpError struct {
	Op         string // E.g. "read handshake", "serve", "reply".
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Err        error // Inner error
}

func newOpErr(op string, addrSrc any, err error) *OpError {
	e := &OpError{
		Op:  op,
		Err: err,
	}
	switch addrSrc := addrSrc.(type) {
	case net.Conn:
		e.LocalAddr = addrSrc.LocalAddr()
		e.RemoteAddr = addrSrc.RemoteAddr()
	case net.Listener:
		e.LocalAddr = addrSrc.Addr()
		e.RemoteAddr = nil
	default:
		e.LocalAddr = nil
		e.RemoteAddr = nil
	}
	return e
}

func (e *OpError) Error() string {
	// Yeah this is mostly copy-pasted from net.go, thanks Google!
	if e == nil {
		return "<nil>"
	}
	s := e.Op

	// Skip addr if inner err is net.OpError,
	// because net.OpError usually already contains addr info
	if _, ok := e.Err.(*net.OpError); !ok {
		if e.LocalAddr != nil {
			s += " " + e.LocalAddr.String()
		}
		if e.RemoteAddr != nil {
			if e.LocalAddr != nil {
				s += "->"
			} else {
				s += " "
			}
			s += e.RemoteAddr.String()
		}
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *OpError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// A RequestNotHandledError can be received from the error channel when a handshake
// or request is not handled by external code.
type RequestNotHandledError struct {
	Type    string // One of "handshake", "CONNECT", "BIND", "UDP ASSOCIATE"
	Timeout bool   // If the request is not handled in a duration of PeriodAutoDeny
}

func (e *RequestNotHandledError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var reason string
	if e.Timeout {
		reason = "timeout"
	} else {
		reason = "not sent"
	}
	return fmt.Sprintf("%s request not handled (%s)", e.Type, reason)
}

// A RelayError represents errors and address info of TCP traffic relaying
// for CONNECT and BIND requests.
type RelayError struct {
	ClientRemoteAddr net.Addr
	ClientLocalAddr  net.Addr
	HostRemoteAddr   net.Addr
	HostLocalAddr    net.Addr
	Client2HostErr   error
	Host2ClientErr   error
}

func newRelayErr(clientConn, hostConn net.Conn, chErr, hcErr error) *RelayError {
	return &RelayError{
		ClientRemoteAddr: clientConn.RemoteAddr(),
		ClientLocalAddr:  clientConn.LocalAddr(),
		HostRemoteAddr:   hostConn.RemoteAddr(),
		HostLocalAddr:    hostConn.LocalAddr(),
		Client2HostErr:   chErr,
		Host2ClientErr:   hcErr,
	}
}

func (e *RelayError) Error() string {
	return fmt.Sprintf(
		"%s, client to host: %s, host to client: %s",
		relayAddr2str(e.ClientRemoteAddr, e.ClientLocalAddr, e.HostLocalAddr, e.HostRemoteAddr),
		e.Client2HostErr, e.Host2ClientErr,
	)
}

func (e *RelayError) Unwrap() (errs []error) {
	errs = []error{e.Client2HostErr, e.Host2ClientErr}
	return
}
