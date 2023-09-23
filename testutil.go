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
