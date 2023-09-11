package s5i

import (
	"errors"
	"io"
	"reflect"
)

const (
  VerUsrPwd byte = 0x01 // VER byte of the Username/Password Auth
  UsrPwdStatSuccess
)

var (
  ErrAuthFailed = errors.New("auth failed")
)

// A Subnegotiator does subnegotiation after an auth method has been chosen.
type Subnegotiator interface {
  // When subnegotiation begins, the server interface will pass net.Conn to 
  // this func. Implementation should keep the ReadWriter for capsulation use. 
  // If nil Capsulator is returned, NoCap is used instead. 
  // Connection is closed if non-nil error is returned. 
  // S5i will assign LocalAddr and RemoteAddr fields if returned error is 
  // MalformedError. 
  Negotiate(io.ReadWriter) (Capsulator, error)
}

// An Capsulator does encapsulation and decapsulation as corresponding auth method 
// requires. 
type Capsulator interface {
  // Used for TCP connections. Connection is closed if non-nil error is returned. 
  io.ReadWriter 

  // Used for UDP packets. Packet is dropped if non-nil error is returned. 
  EncapPacket(p []byte) ([]byte, error)
  DecapPacket(p []byte) ([]byte, error)
}

// Subnegotiator for auth method NO AUTHENTICATION. 
type NoAuthSubneg struct {}

func (n NoAuthSubneg) Negotiate(rw io.ReadWriter) (Capsulator, error) {
  return NoCap{
    rw: rw,
  }, nil
}

// Capsulator that doesn't encauplate/decapsulate at all. 
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

// Subnegotiator for Username/Password Authentication, implements RFC 1929. 
type UsrPwdSubneg struct {
  // List of username password pair. 
  // A list entry is to be ignored if its number of elements is not 2. 
  List [][]byte 
}

func (n UsrPwdSubneg) Negotiate(rw io.ReadWriter) (c Capsulator, err error) {
  var ver byte
  ver, err = readByte(rw)
  if err != nil  {
    return nil, err
  }
  if ver != VerUsrPwd {
    return nil, ErrMalformed
  }

  var ulen, plen byte
  var uname, passwd []byte
  if ulen, err = readByte(rw); err != nil {
    return nil, err
  }
  uname = make([]byte, ulen)
  if plen, err = readByte(rw); err != nil {
    return nil, err
  }
  passwd = make([]byte, plen)

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
