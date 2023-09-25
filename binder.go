package socksy5

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Binder handles the BND requests. 
// It has basic features, thus you need to implement a handling mechanism yourself 
// if Binder doesn't suit your need. 
type Binder struct {
	// Address of the Server, without port, not to be confused with listening address.
	// This is the address that will be sent in the first BND reply.
	// Once parsed, changing it won't be effective.
	LocalAddress string
	localAddress *AddrPort

	mux       sync.Mutex
	listeners map[string]*bindListener
}

// Handle handles the BND request, blocks until error or successful bind. 
// It doesn't wait til all later transmission to finish. 
// If restrict is true, only inbound specified in the request will be accepted. 
func (b *Binder) Handle(req *BindRequest, laddr string, restrict bool, ddl time.Time) error {
  // TODO damn i forgot to utilize ddl!
	b.mux.Lock()
	if b.listeners == nil {
		b.listeners = make(map[string]*bindListener)
	}
	if b.localAddress == nil {
		b.parseLocalAddr()
	}
	b.mux.Unlock()

  var laddrIPs []net.IP
  var port string
	if laddr == "" {
    laddrIPs = []net.IP{net.IPv4zero, net.IPv6zero}
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
    if err != nil {
      req.Deny(RepGeneralFailure, "")
      return err
    }
  }

	sub := &bindSubscriber{
		connChan: make(chan net.Conn),
		dstAddr:  req.dst.String(),
		restrict: restrict,
	}
	listeners, err := b.getListeners(laddrIPs, port, sub, port=="0")
	if err != nil {
    req.Deny(RepGeneralFailure, "")
		return err
	}
  
  bndAddr := b.localAddress.cpy()
  _, lport, err := net.SplitHostPort(listeners[0].laddr)
  if err != nil {
    req.Deny(RepGeneralFailure, "")
    return fmt.Errorf("impossible bug! %w", err)
  }
  var ok bool
  if bndAddr.Port, ok = parseUint16(lport); !ok {
    req.Deny(RepGeneralFailure, "")
    return fmt.Errorf("impossible bug! parse %s failed", listeners[0].laddr)
  }
  
  if ok := req.Accept(bndAddr.String()); !ok {
    return ErrAcceptOrDenyFailed
  }

	conn := <-sub.connChan
  if ok := req.Bind(conn); !ok {
    return ErrAcceptOrDenyFailed
  }
  for _, l := range listeners {
    l.unsubscribe(sub)
  }
  // Clean up
  for {
    select {
    case discard := <-sub.connChan:
      discard.Close()
    default:
      return nil
    }
  }
}

func (b *Binder) getListeners(ips []net.IP, port string, s *bindSubscriber, justOne bool) ([]*bindListener, error) {
	b.mux.Lock()
	defer b.mux.Unlock()

	newListeners := make([]*bindListener, 0)
	result := make([]*bindListener, len(ips))
	var err error
	for i, ip := range ips {
		addr := net.JoinHostPort(ip.String(), port)
		l := b.listeners[addr]
		if l == nil {
			l = new(bindListener)
			if err = l.listen(addr, b); err != nil {
				break
			}
			newListeners = append(newListeners, l)
		}
		result[i] = l
    if justOne {
      break
    }
	}

  if err != nil {
    for _, l := range newListeners {
			l.inner.Close()
    }
    return nil, err
  } else {
    for _, l := range newListeners {
      b.listeners[l.laddr] = l
      go l.run()
    }
    for _, l := range result {
      l.subscribe(s)
    }
    return result, nil
  }
}

func (b *Binder) parseLocalAddr() {
	b.localAddress = new(AddrPort)
	if ipAddr, err := netip.ParseAddr(b.LocalAddress); err == nil {
		if ipAddr.Is4() {
			b.localAddress.Type = ATYPV4
		} else {
			b.localAddress.Type = ATYPV6
		}
		raw, _ := ipAddr.MarshalBinary()
		b.localAddress.Bytes = cpySlice(raw)
	} else {
		b.localAddress.Type = ATYPDOMAIN
		b.localAddress.Bytes = []byte(b.LocalAddress)
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
		for _, s := range bl.subscribers {
			if !s.restrict || s.dstAddr == conn.RemoteAddr().String() {
				s.connChan <- conn
        sent = true
				break
			}
		}
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
	connChan chan net.Conn
	dstAddr  string
	restrict bool
}
