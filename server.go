// Package s5i provides a SOCKS5 server that lets external code accept/deny requests and attach outbound connections.
package s5i

import (
	"errors"
	"net"
	"sync"
	"time"
)

const (
	// Channel capacity of all server interface's outgoing channels
	ChanCap = 64
	// Time to close connection if auth failed, e.t.c..
	PeriodCloseErr = time.Second * time.Duration(8)
)

type Server struct {
	addr        *net.TCPAddr
	listener    *net.TCPListener
	mux         sync.Mutex
	logChan     chan LogEntry
	hndshkChan  chan *HandshakeRequest
	requestChan chan any
	started     bool
	down        bool
	closers     map[closer]struct{}
}

// Starts the server interface. No-op if it was started once.
func (s *Server) Start(addr string) (err error) {
	if s.started {
		return nil
	}
	s.started = true // mux is not needed here

	if s.addr, err = net.ResolveTCPAddr("tcp", addr); err != nil {
		return err
	}

	if s.listener, err = net.ListenTCP(s.addr.Network(), s.addr); err != nil {
		return err
	}

	s.regClosable(s.listener)
	s.info(nil, "listener started at", s.listener.Addr())

	go s.listen()
	return
}

func (s *Server) Running() bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.started && !s.down
}

// Close makes the server stops listening for new handshakes.
// This calls Close() on the internal listener.
func (s *Server) Close() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.down = true
	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
    s.warn(&OpError{ Op: "close listener", Err: err})
	}
	delete(s.closers, s.listener)
}

// CloseAll closes the internal listener and all connections.
// If anything except the internal listener has failed to close,
// Close() won't be called on it during the future calls of CloseAll().
func (s *Server) CloseAll() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.down = true
	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.warn(&OpError{ Op: "close listener", Err: err })
	}
	delete(s.closers, s.listener)
	for c := range s.closers {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
      s.warn(&OpError{ Op: "close conn", Err: err })
		}
		delete(s.closers, c)
	}
}

func (s *Server) regClosable(c closer) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.closers[c] = struct{}{}
}

func (s *Server) delClosable(c closer) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.closers, c)
}

func (s *Server) closeCloser(c closer) {
	err := c.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
    switch c.(type) {
    case net.Conn:
      s.warn(&OpError{ Op: "close conn", Err: err })
    case net.Listener:
      s.warn(&OpError{ Op: "close listener", Err: err })
    default:
      s.warn(&OpError{ Op: "close", Err: err })
    }
	}
	s.delClosable(c)
}

// Gets LogEntry channel from the Server.
// LogEntries are discarded if channel is full or this func is not ever called.
func (s *Server) LogChan() <-chan LogEntry {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.logChan == nil {
		s.logChan = make(chan LogEntry, ChanCap)
	}
	return (<-chan LogEntry)(s.logChan)
}

// Gets handshake request structs from the server.
// Handshakes are rejected by closing connection if channel is full or this func
// is not ever called.
func (s *Server) HandshakeChan() <-chan *HandshakeRequest {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.hndshkChan == nil {
		s.hndshkChan = make(chan *HandshakeRequest, ChanCap)
	}
	return (<-chan *HandshakeRequest)(s.hndshkChan)
}

// Gets channel that receives requests from the Server.
// It's guaranteed that it will receive one of *ConnectRequest,
// *BindRequest and *AssocRequest.
// Requests are denied if channel is full or this func is not ever called.
func (s *Server) RequestChan() <-chan any {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.requestChan == nil {
		s.requestChan = make(chan any, ChanCap)
	}
	return (<-chan any)(s.requestChan)
}

func (s *Server) listen() {
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			s.mux.Lock()
			defer s.mux.Unlock()
			if !s.down {
        s.err(&OpError{ Op: "listen", Err: err })
				s.down = true
			}
			return
		}

		s.regClosable(conn)

		go s.serveClient(conn)
	}
}

func (s *Server) serveClient(conn *net.TCPConn) {
	hs, err := readHandshakeRequest(conn)
	if err != nil {
		s.err(&OpError{
			Op:         "read handshake",
			LocalAddr:  conn.LocalAddr(),
			RemoteAddr: conn.RemoteAddr(),
			Err:        err,
		})
		s.closeCloser(conn)
		return
	}

	sent := s.selectMethod(&hs)

	if !sent {
		s.warn(nil, &OpError{
			Op:         "serve",
			LocalAddr:  conn.LocalAddr(),
			RemoteAddr: conn.RemoteAddr(),
			Err:        &RequestNotHandledError{Type: "handshake"},
		})
		s.closeCloser(conn)
		return
	}

	capper, err := hs.neg.Negotiate(conn)
	if err != nil {
		e := &OpError{
			Op:  "subnegotiate",
			Err: err,
		}
    foo := new(net.OpError)
		if errors.As(err, &foo) {
			s.err(e)
		} else {
			e.LocalAddr = conn.LocalAddr()
			e.RemoteAddr = conn.RemoteAddr()
      if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrMalformed){
        s.warn(e)
      } else {
        s.err(e)
      }
		}

		time.AfterFunc(PeriodCloseErr, func() {
			s.closeCloser(conn)
		})

		return
	}

	if capper == nil {
		capper = NoCap{}
	}

	req, err := readRequest(capper)
	if err != nil {
    foo := new(net.OpError)
		if errors.As(err, &foo) {
			s.err(err)
		} else {
			s.err(&OpError{
				Op:         "read request",
				LocalAddr:  conn.LocalAddr(),
				RemoteAddr: conn.RemoteAddr(),
				Err:        err,
			})
		}
		s.closeCloser(conn)
		return
	}

	req.laddr = conn.LocalAddr()
	req.raddr = conn.RemoteAddr()
	req.once = new(sync.Once)

	switch req.cmd {
	case CmdCONNECT:
		s.handleConnect(&ConnectRequest{
			RequestMsg: *req,
		})
	case CmdBIND:
		s.handleBind(&BindRequest{
			RequestMsg: *req,
		})
	case CmdASSOC:
		s.handleAssoc(&AssocRequest{
			RequestMsg: *req,
		})
	default:
		reply := []byte{
			VerSOCKS5,
			RepCmdNotSupported,
			RSV,
			ATYPV4,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}

		s.warn(&OpError{
			Op:         "serve",
			LocalAddr:  conn.LocalAddr(),
			RemoteAddr: conn.RemoteAddr(),
			Err:        &CmdNotSupportedError{Cmd: req.cmd},
		})
		_, err := capper.Write(reply)
    if err != nil {
      s.err(&OpError{ Op: "deny request", Err: err })
    }

		time.AfterFunc(PeriodCloseErr, func() {
			s.closeCloser(conn)
		})
	}
	return
}

func (s *Server) handleConnect(r *ConnectRequest)

func (s *Server) handleBind(r *BindRequest)

func (s *Server) handleAssoc(r *AssocRequest)

func (s *Server) selectMethod(r *HandshakeRequest) (sent bool) {
	r.wg.Add(1)
	s.mux.Lock()
	if s.hndshkChan != nil {
		s.mux.Unlock()
		select {
		case s.hndshkChan <- r:
			sent = true
			r.wg.Wait()
		default:
		}
	} else {
		s.mux.Unlock()
	}
	return
}

func (s *Server) sendRequest(r any) (sent bool) {
	s.mux.Lock()
	if s.requestChan != nil {
		s.mux.Unlock()
		select {
		case s.requestChan <- r:
			sent = true
		default:
		}
	} else {
		s.mux.Unlock()
	}
	return
}
