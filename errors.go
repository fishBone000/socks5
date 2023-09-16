package socksy5

import (
	"errors"
	"fmt"
	"net"
)

// ErrMalformed is returned when request/response does not follow SOCKS5 protocol. 
var ErrMalformed = errors.New("malformed")

// An OpError contains Op string describing in which operation has the error occured. 
type OpError struct {
	Op         string // E.g. "read handshake", "serve", "close listener". 
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Err        error // Inner error
}

func newOpErr(op string, addrSrc any, err error) *OpError {
  e := &OpError{
    Op: op,
    Err: err,
  }
  e.fillAddr(addrSrc)
  return e
}

func (e *OpError) Error() string {
	// Yeah this is mostly copy-pasted from net.go, thanks Google!
	if e == nil {
		return "<nil>"
	}
	s := e.Op
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
	s += ": " + e.Err.Error()
	return s
}

func (e *OpError) Unwrap() error {
	return e.Err
}

func (e *OpError) fillAddr(a any) *OpError {
  switch x := a.(type) {
  case net.Conn:
    e.LocalAddr = x.LocalAddr()
    e.RemoteAddr = x.RemoteAddr()
  case net.Listener:
    e.LocalAddr = x.Addr()
    e.RemoteAddr = nil
  default:
    e.LocalAddr = nil
    e.RemoteAddr = nil
  }
  return e
}

type CmdNotSupportedError struct {
	Cmd byte
}

func (e *CmdNotSupportedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("CMD 0x%02X not supported", e.Cmd)
}

// A RequestNotHandledError can be received from the error channel when a handshake 
// or request is not handled by external code. 
type RequestNotHandledError struct {
	Type string // One of "handshake", "CONNECT", "BIND", "UDP ASSOCIATE"
}

func (e *RequestNotHandledError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s request not handled")
}
