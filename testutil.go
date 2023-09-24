// test.go contains utils used for testing
package socksy5

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"reflect"
	"sync"
	"time"
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

func randAddr() *AddrPort {
	addr := new(AddrPort)
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
	addr.Port = uint16(rand.Intn(0x1_0000))
	_, err := crand.Read(addr.Bytes)
	if err != nil {
		panic(err)
	}
	return addr
}

func randBool() bool {
	return rand.Int()%2 > 0
}

func randIntExcept(n int, not ...int) int {
	m := rand.Intn(n)
	for isIntOneOf(m, not...) {
		m = rand.Intn(n)
	}
	return m
}

type pipeConn struct {
	net.Conn
	laddr net.Addr
	raddr net.Addr
}

func newPipeConn(addrA, addrB net.Addr) (a, b *pipeConn) {
	a = new(pipeConn)
	b = new(pipeConn)
	a.Conn, b.Conn = net.Pipe()
	a.laddr = addrA
	a.raddr = addrB
	b.laddr = addrB
	b.raddr = addrA
	return
}

func (c *pipeConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *pipeConn) RemoteAddr() net.Addr {
	return c.raddr
}

func chkIntegrity(a, b io.ReadWriteCloser) error {
	wErrChan := make(chan error, 2)
	rErrChan := make(chan error, 2)
	data := make([]byte, 1_000_000)
	wg := new(sync.WaitGroup)
	wg.Add(2)

	send := func(w io.Writer) {
		_, err := w.Write(data)
		wErrChan <- err
		wg.Done()
	}

	rcv := func(r io.Reader) {
		rData, err := io.ReadAll(r)
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		if err == nil {
			if len(rData) != len(data) {
				err = errors.New(fmt.Sprintf(
					"received incorrect size of data, expected %d Bytes, got %d Bytes",
					len(data), len(rData),
				))
			} else if !reflect.DeepEqual(data, rData) {
				err = errors.New("data integrity compromised")
			}
		}
		rErrChan <- err
	}

	go send(a)
	go rcv(a)
	go send(b)
	go rcv(b)

	wg.Wait()
	// Sleep a while to finish writing
	time.Sleep(time.Millisecond * 50)

	for i := 0; i < 2; i++ {
		err := <-wErrChan
		if err != nil {
			return err
		}
	}
	a.Close()
	for i := 0; i < 2; i++ {
		err := <-rErrChan
		if err != nil {
			return err
		}
	}
	return nil
}

func readReply(r io.Reader) (*reply, error) {
	rBuffer := make([]byte, 3)
	_, err := io.ReadFull(r, rBuffer)
	if err != nil {
		return nil, err
	}

	if rBuffer[0] != VerSOCKS5 {
		return nil, errors.New(fmt.Sprintf("malformed reply: VER = %02X", rBuffer[0]))
	}

	if rBuffer[2] != RSV {
		return nil, errors.New(fmt.Sprintf("malformed reply: RSV = %02X", rBuffer[2]))
	}

	addr, err := readAddrPort(r)
	if err != nil {
		return nil, err
	}

	rply := new(reply)
	rply.rep = rBuffer[1]
	rply.addr = addr
	return rply, nil
}

type clSubneg interface {
	Subnegotiator
	getServerSubneg() Subnegotiator
	String() string
	shouldFail() bool
	chkErr() (ok bool)
}

type clNoAuthSubneg struct {
	NoAuthSubneg
}

func (n clNoAuthSubneg) getServerSubneg() Subnegotiator {
	return NoAuthSubneg{}
}

func (n clNoAuthSubneg) String() string {
	s := ""
	s += fmt.Sprintf("  TYPE NO AUTH\n")
	return s
}

func (n clNoAuthSubneg) shouldFail() bool {
	return false
}

func (n clNoAuthSubneg) chkErr() (ok bool) {
	return false
}

type clUsrPwdSubneg struct {
	UsrPwdSubneg
	usr []byte
	pwd []byte
  raw []byte

	malfVer       bool
	shallFailAuth bool
}

func newClUsrPwdSubneg() *clUsrPwdSubneg {
  neg := new(clUsrPwdSubneg)
  neg.usr = make([]byte, rand.Intn(256))
  neg.pwd = make([]byte, rand.Intn(256))

  if _, err := crand.Read(neg.usr); err != nil {
    panic(err)
  }
  if _, err := crand.Read(neg.pwd); err != nil {
    panic(err)
  }

	ulen := len(neg.usr)
	plen := len(neg.pwd)
	raw := make([]byte, 1+1+ulen+1+plen)
	raw[0] = VerUsrPwd
	raw[1] = byte(ulen)
	copy(raw[2:], neg.usr)
	raw[2+ulen] = byte(plen)
	copy(raw[2+ulen+1:], neg.pwd)

  neg.malfVer = randBool()

  if neg.malfVer {
    raw[0] = byte(randIntExcept(256, int(VerUsrPwd)))
  }

  neg.List = make([][][]byte, rand.Intn(5))
  for _, pair := range neg.List {
    pair[0] = make([]byte, rand.Intn(256))
    pair[1] = make([]byte, rand.Intn(256))
    if _, err := crand.Read(pair[0]); err != nil {
      panic(err)
    }
    if _, err := crand.Read(pair[0]); err != nil {
      panic(err)
    }
  }

  i := rand.Intn(5)
  if i < len(neg.List) {
    neg.List[i][0] = neg.usr
    neg.List[i][1] = neg.pwd
  } else {
    neg.shallFailAuth = true
  }

  return neg
}

func (n *clUsrPwdSubneg) Negotiate(rw io.ReadWriter) (Capsulator, error) {
	if _, err := rw.Write(n.raw); err != nil {
		return nil, err
	}

  if n.malfVer {
    return NoCap{}, nil
  }

  rBuffer := make([]byte, 2)
  if _, err := io.ReadFull(rw, rBuffer); err != nil {
    return nil, err
  }
  if rBuffer[0] != VerUsrPwd {
    return nil, errors.New(fmt.Sprintf("server replied subneg with VER %02X", rBuffer[0]))
  }
  if !n.shallFailAuth != (rBuffer[1] == 0x00) {
    msg := "server "
    if rBuffer[1] == 0x00 {
      msg += "accepted "
    } else {
      msg += "rejected "
    }
    msg += "subnegotiation, but we expected "
    if n.shallFailAuth {
      msg += "rejection"
    } else {
      msg += "acceptance"
    }
    return nil, errors.New(msg)
  }
  return NoCap{}, nil
}

func (n *clUsrPwdSubneg) getServerSubneg() Subnegotiator {
	return n.UsrPwdSubneg
}

func (n *clUsrPwdSubneg) String() string {
  s := ""
  s += fmt.Sprintf("  TYPE USR/PWD\n")
  s += fmt.Sprintf("  USR %02X\n", n.usr)
  s += fmt.Sprintf("  PWD %02X\n", n.pwd)
  for i, pair := range n.List {
    s += fmt.Sprintf("    LIST ENTRY %d USR %02X\n", i, pair[i][0])
    s += fmt.Sprintf("    LIST ENTRY %d PWD %02X\n", i, pair[i][1])
  }
  s += fmt.Sprintf("  MALF VER %t\n", n.malfVer)
  s += fmt.Sprintf("  SHALL FAIL AUTH %t\n", n.shallFailAuth)
  s += fmt.Sprintf("  RAW %02X\n", n.raw)
  return s
}

func (n *clUsrPwdSubneg) shouldFail() bool {
  return n.malfVer || n.shallFailAuth
}

// Subnegotiator for capsulation test
// It also implements Capsulator for convinience
type capNeg struct {
  rw io.ReadWriter
}

func (cp *capNeg) Negotiate(rw io.ReadWriter) (Capsulator, error) {
  cp.rw = rw

  raw := make([]byte, 5)
  for i := range raw {
    raw[i] = byte(i)
  }
  
  if _, err := rw.Write(raw); err != nil {
    return nil, err
  }

  rBuffer := make([]byte, 5)
  if _, err := io.ReadFull(rw, rBuffer); err != nil {
    return nil, err
  }
  
  if !reflect.DeepEqual(rBuffer, raw) {
    return nil, ErrMalformed
  }

  return cp, nil
}

func (cp *capNeg) getServerSubneg() Subnegotiator {
  return cp
}

func (cp *capNeg) String() string {
  return fmt.Sprintf("  TYPE CAPSULATION TEST SUBNEGOTIATOR\n")
}

func (cp *capNeg) shouldFail() bool {
  return false
}

func (cp *capNeg) chkErr() bool {
  return false
}

func (cp *capNeg) Read(p []byte) (n int, err error) {
  n, err = cp.rw.Read(p)
  for i := 0; i < n; i++ {
    p[i] ^= 0xFF
  }
  return
}

func (cp *capNeg) Write(p []byte) (n int, err error) {
  q := make([]byte, len(p))
  copy(q, p)
  for i := range q {
    q[i] ^= 0xFF
  }
  n, err = cp.rw.Write(q)
  return
}

func (cp *capNeg) EncapPacket(p []byte) ([]byte, error) {
  return nil, nil
}

func (cp *capNeg) DecapPacket(p []byte) ([]byte, error) {
  return nil, nil
}
