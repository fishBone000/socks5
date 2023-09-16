package socksy5

import (
	"net"
	"strconv"

	"github.com/asaskevich/govalidator"
)

// A Connector is a simple outbound dialer that utilizes [net.Dial].
type Connector struct {
}

func (c *Connector) Dial(addr *Addr, port uint16) (net.Conn, error) {
	return net.Dial(mapIp2Tcp(addr.Network()), addr.String()+":"+strconv.Itoa(int(port)))
}

// A Binder fulfills a SOCKS5 client's BIND request.
type Binder struct {
	HintAddr *Addr
	HintPort uint16

	conn net.Conn
	l    net.Listener
  addr Addr
  port uint16
}

// Start starts the binder. Start doesn't block.
//
// If the HintAddr is not nil, Binder will try listening on HintAddr and HintPort
// first. If Binder fails to do so, or HintAddr is nil, it will:
// - fallback to 0.0.0.0:0, if ATYP is ATYPV4
// - fallback to [::0]:0, if ATYP is ATYPV6
// - try to resolve addr, then fallback to one of the address above accordingly,
// if ATYP is ATYPDOMAIN
// - return [net.UnknownNetworkError], if otherwise.
func (b *Binder) Start(addr Addr, port uint16) (net.Addr, error) {
  var l net.Listener
  var err error

  if b.HintAddr != nil {
    l, err = net.Listen(
      mapIp2Tcp(b.HintAddr.Network()),
      b.HintAddr.String()+":"+strconv.Itoa(int(b.HintPort)),
    )
  }

	if err != nil || b.HintAddr == nil {
		var laddr string
		switch addr.Type {
		case ATYPDOMAIN:
			raddr, err := net.ResolveIPAddr("ip", addr.String())
			if err != nil {
				return nil, err
			}
			if govalidator.IsIPv6(raddr.IP.String()) {
				laddr = "[::0]:0"
			} else {
				laddr = "0.0.0.0:0"
			}
		case ATYPV4:
			laddr = "0.0.0.0:0"
		case ATYPV6:
			laddr = "[::0]:0"
		}

    l, err = net.Listen("tcp", laddr)
	}

  if err != nil {
    return nil, err
  }
  b.l = l
  return l.Addr(), nil
}

func (b *Binder) Accept()
