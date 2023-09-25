package socksy5

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Binder struct {
	// Address of the Server, without port, not to be confused with listening address.
	// This is the address that will be sent in the first BND reply.
	// Once parsed, changing it won't be effective.
	LocalAddress string
	localAddress *AddrPort

	mux       sync.Mutex
	listeners map[string]*bindListener
}

func (b *Binder) Handle(req *BindRequest, laddr string, restrict bool, ddl time.Time) error {
	b.mux.Lock()
	if b.listeners == nil {
		b.listeners = make(map[string]*bindListener)
	}
	if b.localAddress == nil {
		b.parseLocalAddr()
	}
	b.mux.Unlock()

	// Fall back to unspecified, if...laddr is unspecified.
	if laddr == "" {
		laddrType := req.dst.Type
		if laddrType == ATYPDOMAIN {
			ips, err := net.LookupIP(string(req.dst.Bytes))
			if err != nil {
        req.Deny(RepGeneralFailure, "")
				return err
			}
			if netip.MustParseAddr(ips[0].String()).Is4() {
				laddrType = ATYPV4
			} else {
				laddrType = ATYPV6
			}
		} else if laddrType != ATYPV4 && laddrType != ATYPV6 {
      req.Deny(RepAddrTypeNotSupported, "")
			return net.UnknownNetworkError(fmt.Sprintf("0x%02X", laddrType))
		}

		switch laddrType {
		case ATYPV4:
			laddr = "0.0.0.0:0"
		case ATYPV6:
			laddr = "[::]:0"
		}
	}

	host, port, err := net.SplitHostPort(laddr)
	if err != nil {
    req.Deny(RepGeneralFailure, "")
		return err
	}

	laddrIPs, err := net.LookupIP(host)
	if err != nil {
    req.Deny(RepGeneralFailure, "")
		return err
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
    return fmt.Errorf("socks5 bug! %w", err)
  }
  var ok bool
  if bndAddr.Port, ok = parseUint16(lport); !ok {
    req.Deny(RepGeneralFailure, "")
    return fmt.Errorf("socks5 bug! parse %s failed", listeners[0].laddr)
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
    discard, ok := <-sub.connChan
    if !ok {
      break
    }
    discard.Close()
  }
  return nil
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
			l.subscribe(s)
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

	for _, l := range newListeners {
		if err != nil {
			l.inner.Close()
		} else {
			b.listeners[l.laddr] = l
			go l.run()
		}
	}

	return result, err
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

		for _, s := range bl.subscribers {
			if !s.restrict || s.dstAddr == conn.RemoteAddr().String() {
				s.connChan <- conn
				break
			}
		}
	}
}

func (bl *bindListener) Close() {
	bl.mux.Lock()
	defer bl.mux.Unlock()
	if bl.closed {
		return
	}

	bl.binder.mux.Lock()
	defer bl.binder.mux.Unlock()

	delete(bl.binder.listeners, bl.laddr)
	bl.closed = true

	bl.inner.Close()
}

type bindSubscriber struct {
	connChan chan net.Conn
	dstAddr  string
	restrict bool
}
