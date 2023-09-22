// test.go contains utils used for testing
package socksy5

import (
	crand "crypto/rand"
	"io"
	"math/rand"
	"net"
)

type sliceReader struct {
	bytes []byte
	n     int
}

func newSliceReader(b []byte) *sliceReader {
	bytes := make([]byte, len(b))
	copy(bytes, b)
	return &sliceReader{
		bytes: bytes,
	}
}

func (r *sliceReader) Read(p []byte) (n int, err error) {
	if len(r.bytes[r.n:]) == 0 {
		return 0, io.EOF
	}
	n = copy(p, r.bytes[r.n:])
	r.n += n
	return n, nil
}

func randAddr() *Addr {
	addr := new(Addr)
	n := rand.Intn(3)
	switch n {
	case 0:
		addr.Type = ATYPV4
		addr.Bytes = make([]byte, 4)
	case 1:
		addr.Type = ATYPV6
		addr.Bytes = make([]byte, 16)
	case 2:
		addr.Type = ATYPDOMAIN
		addr.Bytes = make([]byte, rand.Intn(256))
	}
	crand.Read(addr.Bytes)
	return addr
}

func randBool() bool {
	return rand.Int()%2 > 0
}

func randIntExcept(n int, not ...int) int {
	m := rand.Intn(n)
	for isIntOneOf(n, not...) {
		m = rand.Intn(n)
	}
	return m
}

type pipeConn struct {
  r *io.PipeReader
  w *io.PipeWriter
  laddr net.Addr
  raddr net.Addr
}

func newPipeConn(addrA, addrB net.Addr) (a, b *pipeConn) {
  a = new(pipeConn)
  b = new(pipeConn)
  a.r, b.w = io.Pipe()
  b.r, a.w = io.Pipe()
  a.laddr = addrA
  a.raddr = addrB
  b.laddr = addrB
  b.raddr = addrA
  return
}
