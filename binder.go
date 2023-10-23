package socksy5

import (
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

// Binder handles the BND requests.
//
// Binder can listen for inbounds for different requests on the same port.
// Thus it is totally ok if you want to handle for multiple requests on one
// fixed port. Although, please note that, if Binder is not listening for
// any inbound on a port, the listener on that port will be closed,
// and will only be created again when next time Binder is required to listen
// on that port.
//
// Currently if req is to be denied, only [RepGeneralFailure]
// will be replied.
type Binder struct {
	// Hostname of the server, not to be confused with listening address.
	// This is the address that will be sent in the first BND reply.
	// RFC 1928 states that the addresses in replies to BIND requests shall
	// be IP addresses, but a host name is considered valid here.
	// Do not modify this field when Binder is running.
	Hostname string

	mux         sync.Mutex
	dispatchers map[string]*tcpDispatcher
}

// Handle handles the BND request, blocks until error or successful bind.
// It can be called simultainously.
//
// addr represents the address to listen at, and it can be empty,
// in this case Handle will listen on 0.0.0.0 and :: with one single
// system allocated port.
// If the host part in addr is a host name,
// Handle will resolve it to IP addresses and listen on all of them.
// If the port in addr is 0,
// Handle will try to use one single system allocated port for all of them.
//
// Handle doesn't wait for the data transmission after the 2nd reply to finish.
//
// timeout is disabled if it's 0.
func (b *Binder) Handle(req *BindRequest, addr string, timeout time.Duration) error {
	cancel := make(chan struct{})
	if timeout != 0 {
		time.AfterFunc(timeout, func() {
			close(cancel)
		})
	}

	b.mux.Lock()
	if b.dispatchers == nil {
		b.dispatchers = make(map[string]*tcpDispatcher)
	}
	b.mux.Unlock()

	dstIPs, err := net.LookupIP(req.Dst().Host())
	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return err
	}

	select {
	case <-cancel:
		req.Deny(RepGeneralFailure, "")
		return os.ErrDeadlineExceeded
	default:
	}

	dispatchers, err := b.getDispatchers(addr)
	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return err
	}

	_, port, _ := net.SplitHostPort(dispatchers[0].listener.Addr().String())

	ready := make(chan struct{})
	var conn net.Conn
	connChan := make(chan net.Conn)
	errChan := make(chan error)
	defer close(connChan)
	go func() {
		conn = <-connChan
		close(ready)
	}()
	err = nil
	for _, l := range dispatchers {
		for _, ip := range dstIPs {
			addr := net.JoinHostPort(ip.String(), port)
			if existed := l.subscribe(addr, connChan, errChan); existed {
				err = ErrDuplicatedRequest
				continue
			}
			defer l.unsubscribe(addr)
		}
	}

	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return err
	}

	if ok := req.Accept(net.JoinHostPort(b.Hostname, port)); !ok {
		return ErrAcceptOrDenyFailed
	}

	err = nil
	select {
	case <-cancel:
		err = os.ErrDeadlineExceeded
	case err = <-errChan:
	case <-ready:
	}

	if err != nil {
		go func() {
			<-ready
			if conn != nil {
				conn.Close()
			}
		}()
		req.Deny(RepGeneralFailure, "")
		return err
	}

	if ok := req.Bind(conn); !ok {
		return ErrAcceptOrDenyFailed
	}

	return nil
}

func (b *Binder) getDispatchers(addr string) ([]*tcpDispatcher, error) {
	var ips []net.IP
	var port string
	if addr == "" {
		if runtime.GOOS == "dragonfly" || runtime.GOOS == "openbsd" {
			ips = []net.IP{net.IPv4zero, net.IPv6zero}
		} else {
			ips = []net.IP{net.IPv4zero}
		}
		port = "0"
	} else {
		var host string
		var err error
		host, port, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		ips, err = net.LookupIP(host)
		if err != nil {
			return nil, err
		}
	}

	b.mux.Lock()
	defer b.mux.Unlock()
	result := make([]*tcpDispatcher, 0, len(ips))
	newDispatchers := make([]*tcpDispatcher, 0, 4)
	var err error
	for _, ip := range ips {
		d := b.dispatchers[net.JoinHostPort(ip.String(), port)]
		if d != nil {
			result = append(result, d)
			continue
		}
		var l net.Listener
		l, err = net.Listen("tcp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			break
		}
		d = &tcpDispatcher{
			listener:       l,
			connChanByAddr: make(map[string]chan<- net.Conn),
			errChanByAddr:  make(map[string]chan<- error),
			binder:         b,
			mux:            &b.mux,
		}
		result = append(result, d)
		newDispatchers = append(newDispatchers, d)
		if port == "0" {
			_, port, _ = net.SplitHostPort(l.Addr().String())
		}
	}

	if err != nil {
		for _, d := range newDispatchers {
			d.listener.Close()
		}
		return nil, err
	}

	for _, d := range newDispatchers {
		b.dispatchers[d.listener.Addr().String()] = d
		go d.run()
	}

	return result, nil
}

type tcpDispatcher struct {
	listener       net.Listener
	connChanByAddr map[string]chan<- net.Conn
	errChanByAddr  map[string]chan<- error
	mux            *sync.Mutex
	binder         *Binder
}

func (d *tcpDispatcher) subscribe(addr string, connChan chan<- net.Conn, errChan chan<- error) (existed bool) {
	d.mux.Lock()
	defer d.mux.Unlock()
	if ch := d.connChanByAddr[addr]; ch != nil {
		return true
	}
	d.connChanByAddr[addr] = connChan
	d.errChanByAddr[addr] = errChan
	return false
}

func (d *tcpDispatcher) unsubscribe(addr string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	delete(d.connChanByAddr, addr)
	delete(d.errChanByAddr, addr)
	if len(d.connChanByAddr) == 0 {
		d.listener.Close()
		delete(d.binder.dispatchers, d.listener.Addr().String())
	}
}

func (d *tcpDispatcher) run() {
	for {
		conn, err := d.listener.Accept()

		d.mux.Lock()

		if err != nil {
			for _, errChan := range d.errChanByAddr {
				select {
				case errChan <- err:
				default:
				}
			}
			d.mux.Unlock()
			return
		}

		if connChan := d.connChanByAddr[conn.RemoteAddr().String()]; connChan != nil {
			select {
			case connChan <- conn:
				d.mux.Unlock()
				continue
			default:
			}
		}
		conn.Close()
		d.mux.Unlock()
	}
}
