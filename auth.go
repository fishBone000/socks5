package s5i

import (
	"io"
)

// A Subnegotiator does subnegotiation after an auth method has been chosen.
type Subnegotiator interface {
  // When subnegotiation begins, the server interface will pass net.Conn to 
  // this func. Negotiate() should return Capsulator upon finish, or error if
  // any. 
  // Connection is closed if non-nil error is returned. 
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

// Subnegotiator for NO AUTHENTICATION. 
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
