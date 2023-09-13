// Package socksy5 provides a SOCKS5 server that reads and sends SOCKS5 messages, 
// act like a proxy when outbound connection is attached, 
// but leaves handshake and  request decisions, outbound dialing, 
// UDP relaying, subnegotiation e.t.c. to external code.
//
// This provides advantages when you need multi-homed BND or UDP ASSOCIATION 
// processing, custom subnegotiation and encryption, attach special connection to 
// CONNECT requests e.t.c.. 
//
// All methods in this package, except for the methods of [Addr], are safe 
// to call simultanously. 
package socksy5

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Constants for server policy. 
const (
	// Channel capacity of all channels returned by Server's channel functions. 
	ChanCap = 64
	// Time to close connection if auth failed, request denied, e.t.c..
	PeriodClose    = time.Second * time.Duration(3)
	PeriodAutoDeny = time.Second * time.Duration(30)
)

// A Server is a SOCKS5 server interface. 
// 
// Use channel funcs (e.g. [Server.HandshakeChan]) to deal with logging, requests e.t.c..
// All channel funcs create a corresponding channel if not ever created.
// If no channel is created or channel is full, corresponding log entries are
// discarded, handshakes, or requests are denied.
type Server struct {
	addr        *net.TCPAddr
	listener    *net.TCPListener
	mux         sync.Mutex
	logChan     chan LogEntry
	hndshkChan  chan *Handshake
	requestChan chan any
	started     bool
	down        bool
	closers     map[closer]struct{}
}

// Start starts the Server. No-op if it has been started. 
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

// Close closes the internal listener. Connections established are not closed. 
func (s *Server) Close() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.down = true
	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.warn(&OpError{Op: "close listener", Err: err})
	}
	delete(s.closers, s.listener)
}

// CloseAll closes the internal listener and all established connections.
// If a connection has failed to close, 
// the [Server] won't try to close it next time. 
func (s *Server) CloseAll() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.down = true
	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.warn(&OpError{Op: "close listener", Err: err})
	}
	delete(s.closers, s.listener)
	for c := range s.closers {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.warn(&OpError{Op: "close conn", Err: err})
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

func (s *Server) closeCloser(c closer) error {
	if c == nil {
		return nil
	}
	err := c.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		switch c.(type) {
		case net.Conn:
			s.warn(&OpError{Op: "close conn", Err: err})
		case net.Listener:
			s.warn(&OpError{Op: "close listener", Err: err})
		default:
			s.warn(&OpError{Op: "close", Err: err})
		}
	}
	s.delClosable(c)
	return err
}

func (s *Server) LogChan() <-chan LogEntry {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.logChan == nil {
		s.logChan = make(chan LogEntry, ChanCap)
	}
	return (<-chan LogEntry)(s.logChan)
}

func (s *Server) HandshakeChan() <-chan *Handshake {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.hndshkChan == nil {
		s.hndshkChan = make(chan *Handshake, ChanCap)
	}
	return (<-chan *Handshake)(s.hndshkChan)
}

// RequestChan is guaranteed to return a channel that receives one of 
// [*ConnectRequest], [*BindRequest] and [*AssocRequest].
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
				s.err(&OpError{Op: "listen", Err: err})
				s.down = true
			}
			return
		}

		s.regClosable(conn)

		go s.serveClient(conn)
	}
}

func (s *Server) serveClient(conn *net.TCPConn) {
	hs, err := readHandshake(conn)
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
	hs.laddr = conn.LocalAddr()
	hs.raddr = conn.RemoteAddr()

	time.AfterFunc(PeriodAutoDeny, hs.Deny)
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

	hsReply := []byte{VerSOCKS5, hs.methodChosen}
	if _, err := conn.Write(hsReply); err != nil {
		s.err(&OpError{
			Op:  "reply handshake",
			Err: err,
		})
		s.closeCloser(conn)
		return
	}
	if hs.methodChosen == MethodNoAccepted {
		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(conn)
		})
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
			if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrMalformed) {
				s.warn(e)
			} else {
				s.err(e)
			}
		}

		time.AfterFunc(PeriodClose, func() {
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
	req.wg.Add(1)

	var wrappedReq any
	switch req.cmd {
	case CmdCONNECT:
		cr := &ConnectRequest{
			Request: *req,
		}
		wrappedReq = cr
		req = &cr.Request
	case CmdBIND:
		br := &BindRequest{
			Request: *req,
		}
		br.reply = nil // Bind() relies on this to check if it's accepted
		br.bindWg.Add(1)
		wrappedReq = br
		req = &br.Request
	case CmdASSOC:
		ar := &AssocRequest{
			Request: *req,
		}
		terminator := func() error {
			go ar.notifyOnce.Do(func() {
				if ar.notify != nil {
					ar.notify(nil)
				}
			})
			return s.closeCloser(conn)
		}
		ar.terminate = terminator
		wrappedReq = ar
		req = &ar.Request
	default:
		s.warn(&OpError{
			Op:         "serve",
			LocalAddr:  conn.LocalAddr(),
			RemoteAddr: conn.RemoteAddr(),
			Err:        &CmdNotSupportedError{Cmd: req.cmd},
		})
	}

	if req.cmd != CmdCONNECT && req.cmd != CmdBIND && req.cmd != CmdASSOC {
		req.deny(RepCmdNotSupported, emptyFQDN, zeroPort)
	} else {
		time.AfterFunc(PeriodAutoDeny, func() {
			req.deny(RepGeneralFailure, emptyFQDN, zeroPort)
		})

		sent = s.evaluateRequest(wrappedReq)

		if sent {
			req.wg.Wait()
		} else {
			s.warn(&OpError{
				Op:         "serve",
				LocalAddr:  conn.LocalAddr(),
				RemoteAddr: conn.RemoteAddr(),
				Err:        &RequestNotHandledError{Type: cmdCode2Str(req.cmd)},
			})
			req.deny(RepGeneralFailure, emptyFQDN, zeroPort)
		}
	}

	raw, _ := req.reply.MarshalBinary()
	if _, err := capper.Write(raw); err != nil {
		s.err(&OpError{Op: "reply request " + cmdCode2Str(req.cmd), Err: err})
		s.closeCloser(conn)
		return
	}

	switch req.cmd {
	case CmdCONNECT:
		s.handleConnect(wrappedReq.(*ConnectRequest), capper, conn)
	case CmdBIND:
		s.handleBind(wrappedReq.(*BindRequest), capper, conn)
	case CmdASSOC:
		s.handleAssoc(wrappedReq.(*AssocRequest), conn)
	}
	return
}

func (s *Server) handleConnect(r *ConnectRequest, capper Capsulator, conn net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(r.conn)
			s.closeCloser(conn)
		})
		return
	}

	s.regClosable(r.conn)

	infoOnce := sync.OnceFunc(func() {
		s.info(nil, "CONNECT connection closed. ")
	})
	go func() {
		io.Copy(capper, conn)
		infoOnce()
		s.closeCloser(r.conn)
		s.closeCloser(conn)
	}()
	go func() {
		io.Copy(conn, capper)
		infoOnce()
		s.closeCloser(r.conn)
		s.closeCloser(conn)
	}()
}

func (s *Server) handleBind(r *BindRequest, capper Capsulator, conn net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(r.conn)
		})
		return
	}

	r.bindWg.Wait()

	raw, _ := r.bindReply.MarshalBinary()
	if _, err := capper.Write(raw); err != nil {
		s.err(&OpError{Op: "reply BND(2nd)", Err: err})
		s.closeCloser(conn)
		return
	}

	infoOnce := sync.OnceFunc(func() {
		s.info(nil, "BND connection closed. ") // TODO make info util
	})
	go func() {
		io.Copy(capper, r.conn)
		infoOnce()
		s.closeCloser(r.conn)
		s.closeCloser(conn)
	}()
	go func() {
		io.Copy(r.conn, capper)
		infoOnce()
		s.closeCloser(r.conn)
		s.closeCloser(conn)
	}()
}

func (s *Server) handleAssoc(r *AssocRequest, conn net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(conn)
			r.terminate()
		})
	}
}

func (s *Server) selectMethod(hs *Handshake) (sent bool) {
	hs.wg.Add(1)
	s.mux.Lock()
	if s.hndshkChan != nil {
		s.mux.Unlock()
		select {
		case s.hndshkChan <- hs:
			sent = true
			hs.wg.Wait()
		default:
		}
	} else {
		s.mux.Unlock()
	}
	return
}

func (s *Server) evaluateRequest(r any) (sent bool) {
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
