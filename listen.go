package socksy5

import "net"

// Listen listens addr and pass connections to ml.
//
// addr can be a host name, in this case Listen will look it up
// and listen on resolved IP addresses.
func Listen(addr string, ml *MidLayer) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}

	listeners := make([]net.Listener, 0, len(ips))
	for _, ip := range ips {
		l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		defer l.Close()
	}

	connChan := make(chan net.Conn)
	errChan := make(chan error)
	stop := make(chan struct{})
	for _, l := range listeners {
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					select {
					case errChan <- err:
					case <-stop:
					}
					return
				}
				connChan <- conn
			}
		}(l)
	}

	go func() {
		for {
			select {
			case conn := <-connChan:
				go ml.ServeClient(conn)
			case <-stop:
				return
			}
		}
	}()

	err = <-errChan
	close(stop)
	return err
}
