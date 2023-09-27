package socksy5

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"
)

// Binder handles the BND requests.
// It has basic features, thus you need to implement a handling mechanism yourself
// if Binder doesn't suit your need.
//
// Binder can listen for inbounds for different requests on the same port.
// Thus it is totally ok if you want to handle for multiple requests on one
// fixed port. Although, please note that, if Binder is not listening for
// any inbound on a port, the listener on that port will be closed,
// and will only be created again when next time Binder is required to listen
// on that port.
//
// The listening port registry is independent
// across different Binders and [Server].
//
// Currently if req is to be denied, only [RepGeneralFailure] 
// will be replied. 
type Binder struct {
	// Hostname of the Server, not to be confused with listening address.
	// This is the address that will be sent in the first BND reply.
	// Once parsed, changing it won't be effective.
	Hostname string
	hostname *AddrPort //

	mux       sync.Mutex
	listeners map[string]*bindListener
}

// Handle handles the BND request, blocks until error or successful bind.
// It can be called simultainously. 
// 
// laddr represents the address to listen at, and it can be empty, 
// in this case Handle will listen on all zero addresses with one single 
// system allocated port. 
// If laddr is a host name, 
// Handle will resolve it to IP addresses and listen on all of them. 
// If the port in laddr is 0, 
// Handle will try to use one single system allocated port for all of them. 
//
// Upon return, if req is not accepted / denied in other goroutines, 
// req will be accepted or denied accordingly and both 2 BND replies will be sent.
// Handle doesn't wait for all later transmission after 2nd reply to finish.
// If restrict is true, only inbound specified in the request will be accepted.
func (b *Binder) Handle(req *BindRequest, laddr string, restrict bool, timeout time.Duration) error {
	cancel := make(chan struct{})
	if timeout != 0 {
		time.AfterFunc(timeout, func() {
			close(cancel)
		})
	}

	b.mux.Lock()
	if b.listeners == nil {
		b.listeners = make(map[string]*bindListener)
	}
	if b.hostname == nil {
		b.parseLocalAddr()
	}
	b.mux.Unlock()

	var laddrIPs []net.IP
	var port string
	if laddr == "" {
		if runtime.GOOS == "dragonfly" || runtime.GOOS == "openbsd" {
			laddrIPs = []net.IP{net.IPv4zero, net.IPv6zero}
		} else {
			laddrIPs = []net.IP{net.IPv4zero}
		}
		port = "0"
	} else {
		var host string
		var err error
		host, port, err = net.SplitHostPort(laddr)
		if err != nil {
			req.Deny(RepGeneralFailure, "")
			return err
		}

		laddrIPs, err = net.LookupIP(host)
		ok := true
		select {
		case _, ok = <-cancel:
		default:
		}
		if err != nil {
			req.Deny(RepGeneralFailure, "")
			return err
		}
		if !ok {
			req.Deny(RepGeneralFailure, "")
			return os.ErrDeadlineExceeded
		}
	}

	sub := &bindSubscriber{
		connChan: make(chan net.Conn),
		dstAddr:  req.dst.String(),
		restrict: restrict,
	}
	listeners, err := b.getListeners(laddrIPs, port, sub)
	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return err
	}

	sub.listeners = listeners
	for _, l := range listeners {
		l.subscribe(sub)
	}
	defer sub.cleanup()

	_, lport, err := net.SplitHostPort(listeners[0].laddr)
	if err != nil {
		req.Deny(RepGeneralFailure, "")
		return fmt.Errorf("impossible bug! %w", err)
	}

	var ok bool
	bndAddr := b.hostname.cpy()
	if bndAddr.Port, ok = parseUint16(lport); !ok {
		req.Deny(RepGeneralFailure, "")
		return fmt.Errorf("impossible bug! parse %s failed", listeners[0].laddr)
	}

	if ok := req.Accept(bndAddr.String()); !ok {
		return ErrAcceptOrDenyFailed
	}

	var conn net.Conn
	ok = true
	select {
	case conn = <-sub.connChan:
	case _, ok = <-cancel:
	}
	if !ok {
		req.DenyBind(RepGeneralFailure, "")
		return os.ErrDeadlineExceeded
	}
	if ok := req.Bind(conn); !ok {
		return ErrAcceptOrDenyFailed
	}
	return nil
}

func (b *Binder) getListeners(ips []net.IP, port string, sub *bindSubscriber) ([]*bindListener, error) {
	b.mux.Lock()
	defer b.mux.Unlock()

	addrOfNewListeners := make([]net.IP, 0, 4)
	result := make([]*bindListener, 0, len(ips))
	var err error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		bndListener := b.listeners[addr]
		if bndListener == nil {
			addrOfNewListeners = append(addrOfNewListeners, ip)
		}
		result = append(result, bndListener)
	}

	newListeners, err := listenMultipleTCP(addrOfNewListeners, port)
	if err != nil {
		return nil, err
	}

	for _, l := range newListeners {
		bndListener := &bindListener{
			inner:  l,
			binder: b,
			laddr:  l.Addr().String(),
		}
		b.listeners[bndListener.laddr] = bndListener
		result = append(result, bndListener)
		go bndListener.run()
	}

	return result, nil
}

func (b *Binder) parseLocalAddr() {
	b.hostname = new(AddrPort)
	if ipAddr, err := netip.ParseAddr(b.Hostname); err == nil {
		if ipAddr.Is4() {
			b.hostname.Type = ATYPV4
		} else {
			b.hostname.Type = ATYPV6
		}
		raw, _ := ipAddr.MarshalBinary()
		b.hostname.Bytes = cpySlice(raw)
	} else {
		b.hostname.Type = ATYPDOMAIN
		b.hostname.Bytes = []byte(b.Hostname)
	}
	return
}

type bindListener struct {
	inner       net.Listener
	closed      bool
	subscribers map[string]*bindSubscriber
	mux         sync.Mutex
	binder      *Binder
	laddr       string
}

// Must subscribe before listen to make map beforehand.
func (bl *bindListener) listen(addr string, b *Binder) (err error) {
	bl.binder = b

	bl.inner, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	actualAddr := bl.inner.Addr()
	if actualAddr == nil {
		return errors.New("listener address is unknown(nil)")
	}

	bl.laddr = actualAddr.String()
	return nil
}

func (bl *bindListener) subscribe(s *bindSubscriber) {
	bl.mux.Lock()
	defer bl.mux.Unlock()
	if bl.subscribers == nil {
		bl.subscribers = make(map[string]*bindSubscriber)
	}
	bl.subscribers[s.dstAddr] = s
}

func (bl *bindListener) unsubscribe(s *bindSubscriber) {
	bl.mux.Lock()
	delete(bl.subscribers, s.dstAddr)
	bl.mux.Unlock()

	if len(bl.subscribers) == 0 {
		bl.Close()
	}
}

func (bl *bindListener) run() {
	for {
		conn, err := bl.inner.Accept()
		if err != nil {
			bl.Close()
			return
		}

		sent := false
		bl.mux.Lock()
		for _, s := range bl.subscribers {
			if !s.restrict || s.dstAddr == conn.RemoteAddr().String() {
				s.connChan <- conn // bindSubscriber.connChan shall not block
				sent = true
				break
			}
		}
		bl.mux.Unlock()

		if !sent {
			conn.Close()
		}
	}
}

func (bl *bindListener) Close() {
	bl.mux.Lock()
	defer bl.mux.Unlock()
	if bl.closed {
		return
	}
	bl.closed = true

	bl.binder.mux.Lock()
	defer bl.binder.mux.Unlock()

	delete(bl.binder.listeners, bl.laddr)

	bl.inner.Close()
}

type bindSubscriber struct {
	connChan  chan net.Conn // bindSubscriber.connChan shall not block
	dstAddr   string
	restrict  bool
	listeners []*bindListener
}

func (bs *bindSubscriber) cleanup() {
	for _, l := range bs.listeners {
		l.unsubscribe(bs)
	}

Loop:
	for {
		select {
		case conn := <-bs.connChan:
			conn.Close()
		default:
			break Loop
		}
	}
}
