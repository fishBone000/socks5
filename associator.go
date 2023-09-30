package socksy5

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
)

var errDispatcherDown = errors.New("dispatcher down")

// ErrAlreadyRelaying is returned by [Associator.Handle] and indicates that
// the [Associator] is already relaying for that client.
var ErrAlreadyRelaying = errors.New("already relaying for that client")

// Associator relays UDP packets for UDP ASSOCIATE requests.
// It has basic functionality, thus if it doesn't suit your need, you need
// to implement a relayer yourself.
//
// All methods of Associator can be called simultaneously.
type Associator struct {
	// Hostname of the server, not to be confused with listening address.
	// This is the address that will be sent in the first BND reply.
	// RFC 1928 states that addresses in replies to UDP ASSOCIATE requests
	// shall be IP addresses, but a host name is considered valid here.
	// Do not modify this field when Associator is running.
	Hostname string

	dispatchers map[string]*udpDispatcher

	mux sync.RWMutex
}

// Handle handles the UDP ASSOCIATE request req.
//
// addr is the address that a will listen for and send UDP packets
// from and to client. It can be empty, in that case a will use
// all zero addresses with system allocated port.
// If the host in addr is FQDN, Handle will look it up and listen
// on all of the resulting IP addresses. If the port in addr is 0,
// a system allocated port will be chosen. Note that if FQDN is
// used in addr, Handle will duplicate host-to-client UDP packets
// and send them out using all of the IP addresses associated with
// the FQDN.
func (a *Associator) Handle(req *AssocRequest, addr string) error {
	a.mux.Lock()
	if a.dispatchers == nil {
		a.dispatchers = make(map[string]*udpDispatcher)
	}
	a.mux.Unlock()

	conn, err := net.ListenUDP("udp", new(net.UDPAddr))
	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return err
	}

	ds, err := a.getDispatchers(addr)
	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return err
	}

	rawChan := make(chan []byte, 8)
	errChan := make(chan error)
	for _, d := range ds {
		existed := d.subscribe(req.Dst().String(), rawChan, errChan)
		if existed {
			req.Deny(RepGeneralFailure, "")
			return ErrAlreadyRelaying
		}
		defer d.unsubscribe(req.Dst().String())
	}

	_, port, err := net.SplitHostPort(ds[0].conn.LocalAddr().String())
	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return err
	}

	stop := make(chan struct{})
	notify := func(err error) {
		select {
		case errChan <- err:
		case <-stop:
		}
	}

	terminate, ok := req.Accept(net.JoinHostPort(a.Hostname, port), notify)
	if !ok {
		return ErrAcceptOrDenyFailed
	}
	defer terminate()

	packet := new(udpPacket)
	capper := req.Capsulation()
	// Relay UDP from client to destination
	go func() {
		for {
			var raw []byte
			select {
			case raw = <-rawChan:
			case <-stop:
				return
			}

			dRaw, err := capper.DecapPacket(raw)
			if err != nil {
				continue
			}
			err = packet.UnmarshalBinary(dRaw)
			if err != nil || packet.frag != 0x00 {
				continue
			}

			_, err = conn.WriteTo(packet.data, packet.dst)
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	// Relay UDP to client
	buffer := make([]byte, 65535)
	go func() {
		for {
			n, src, err := conn.ReadFrom(buffer)
			if n > 0 {
				dst, err := ParseAddrPort(src.String())
				if err != nil {
					panic(fmt.Errorf("impossible bug! err parsing host addr for inbound udp packet: %w", err))
				}
				packet := &udpPacket{
					dst:  dst,
					data: cpySlice(buffer[:n]),
				}
				dRaw, err := packet.MarshalBinary()
				if err != nil {
					panic(fmt.Errorf("impossible bug! err marshaling udp packet: %w", err))
				}
				raw, err := capper.EncapPacket(dRaw)
				if err != nil {
					continue
				}
				for _, d := range ds {
					d.WriteTo(raw, req.Dst())
				}
			}

			if err != nil {
				select {
				case errChan <- err:
				case <-stop:
				}
				return
			}
		}
	}()

	err = <-errChan
	close(stop)
	return nil
}

func (a *Associator) getDispatchers(addr string) ([]*udpDispatcher, error) {
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
		var err error
		var host string
		host, port, err = net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		ips, err = net.LookupIP(host)
		if err != nil {
			return nil, err
		}
	}

	result := make([]*udpDispatcher, 0, len(ips))
	newDispatchers := make([]*udpDispatcher, 0, 4)

	a.mux.Lock()
	defer a.mux.Unlock()
	var err error
	for _, ip := range ips {
		hostPort := net.JoinHostPort(ip.String(), port)
		if d, ok := a.dispatchers[hostPort]; ok {
			result = append(result, d)
			continue
		}

		var laddr *net.UDPAddr
		laddr, err = net.ResolveUDPAddr("udp", hostPort)
		if err != nil {
			break
		}
		var conn *net.UDPConn
		conn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			break
		}
		// Here we share one single RWMutex among associator and its dispatchers.
		// Using different Mutexes on each dispatcher and associator can cause dead lock,
		// sharing one single Mutex can cause performance drop, because only 1
		// dispatcher can do its job at a time, thus we share 1 RWMutex.
		d := &udpDispatcher{
			conn:  conn,
			assoc: a,
			mux:   &a.mux,
		}
		newDispatchers = append(newDispatchers, d)
		result = append(result, d)
	}

	if err != nil {
		for _, d := range newDispatchers {
			d.conn.Close()
		}
		return nil, err
	}

	for _, d := range newDispatchers {
		a.dispatchers[d.conn.LocalAddr().String()] = d
	}

	return result, nil
}

func (a *Associator) deregisterNoLock(addr string) {
	delete(a.dispatchers, addr)
}

type udpDispatcher struct {
	rawChanByAddr map[string]chan<- []byte
	errChanByAddr map[string]chan<- error
	conn          *net.UDPConn
	assoc         *Associator
	mux           *sync.RWMutex
}

func (d *udpDispatcher) subscribe(addr string, rawChan chan<- []byte, errChan chan<- error) (existed bool) {
	d.mux.Lock()
	defer d.mux.Unlock()

	if d.rawChanByAddr == nil || d.errChanByAddr == nil {
		d.rawChanByAddr = make(map[string]chan<- []byte)
		d.errChanByAddr = make(map[string]chan<- error)
	} else if _, ok := d.rawChanByAddr[addr]; ok {
		return true
	}

	d.rawChanByAddr[addr] = rawChan
	d.errChanByAddr[addr] = errChan
	return false
}

func (d *udpDispatcher) unsubscribe(addr string) {
	d.mux.Lock()
	defer d.mux.Unlock()
	delete(d.rawChanByAddr, addr)
	delete(d.errChanByAddr, addr)

	if len(d.rawChanByAddr) == 0 {
		d.closeNoLock(nil)
	}
}

func (d *udpDispatcher) WriteTo(b []byte, addr net.Addr) (int, error) {
	return d.conn.WriteTo(b, addr)
}

func (d *udpDispatcher) closeNoLock(err error) {
	d.assoc.deregisterNoLock(d.conn.LocalAddr().String())
	for _, errChan := range d.errChanByAddr {
		errChan <- err
	}
	d.conn.Close()
	return
}

func (d *udpDispatcher) run() {
	d.mux.Lock()
	if d.rawChanByAddr == nil {
		d.rawChanByAddr = make(map[string]chan<- []byte)
	}
	d.mux.Unlock()

	for {
		buffer := make([]byte, 65535)
		n, addr, err := d.conn.ReadFromUDPAddrPort(buffer)

		d.mux.RLock()
		for cAddr, ch := range d.rawChanByAddr {
			if n == 0 {
				break
			}
			if addr.String() == cAddr {
				select {
				case ch <- buffer[:n]:
				default:
				}
				break
			}
		}

		if err != nil {
			d.mux.RUnlock()
			d.mux.Lock()
			defer d.mux.Unlock()
			d.closeNoLock(err)
			return
		}

		d.mux.RUnlock()
	}
}
