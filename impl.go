package socksy5

import (
	"net"
	"strconv"
)

// A Connector is a simple outbound dialer that utilizes [net.Dial].
type Connector struct {
}

func (c *Connector) Dial(addr *AddrPort, port uint16) (net.Conn, error) {
	return net.Dial(mapIp2Tcp(addr.Network()), addr.String()+":"+strconv.Itoa(int(port)))
}
