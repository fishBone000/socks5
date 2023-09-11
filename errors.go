package s5i

import (
	"errors"
	"fmt"
	"net"
)

var (
  // Request/response is malformed, e.g. incorrect VER byte value, RSV byte is
  // not 0x00
  ErrMalformed = errors.New("malformed")
)

type OpError struct {
  Op string
	LocalAddr  net.Addr
	RemoteAddr net.Addr
  Err error
}

func (e *OpError) Error() string {
  // Yeah this is mostly copy-pasted from net.go
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


type CmdNotSupportedError struct {
	Cmd        byte
}

func (e *CmdNotSupportedError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("CMD 0x%02X not supported", e.Cmd)
}

type RequestNotHandledError struct {
  Type string // One of "handshake", "CONNECT", "BIND", "UDP ASSOCIATE"
}

func (e *RequestNotHandledError) Error() string {
  if e == nil {
    return "<nil>"
  }
	return fmt.Sprintf("%s request not handled")
}
