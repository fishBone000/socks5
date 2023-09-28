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
	"fmt"
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
	listener    *net.TCPListener
	mux         sync.Mutex
	logChan     chan LogEntry
	hndshkChan  chan *Handshake
	requestChan chan any
	up          bool
	closers     map[closer]struct{}
}

// TODO Check nil receivers

// Serve starts the Server and blocks until any error occured or closed by 
// [Server.Close] or [Server.CloseAll]. 
// No-op and no blocking if it has been started. 
//
// [Server.ServeClient] can be invoked without starting the server
// if you want to handle listening yourself.
func (s *Server) Serve(addr string) (err error) {
  s.mux.Lock()
	if s.up {
    s.mux.Unlock()
		return nil
	}
  s.mux.Unlock()

  var tcpAddr *net.TCPAddr
	if tcpAddr, err = net.ResolveTCPAddr("tcp", addr); err != nil {
		return
	}

  s.mux.Lock()
	if s.listener, err = net.ListenTCP(tcpAddr.Network(), tcpAddr); err != nil {
    s.listener = nil
    s.mux.Unlock()
		return
	}
	s.up = true

  if s.closers == nil {
    s.closers = make(map[closer]struct{})
  }
	s.regCloserNoLock(s.listener)
  s.mux.Unlock()

	s.info(newOpErr("start server", s.listener, nil))

	for {
    var conn *net.TCPConn
		conn, err = s.listener.AcceptTCP()
		if err != nil {
			s.mux.Lock()
			defer s.mux.Unlock()
			if !s.up {
				s.err(newOpErr("listen", s.listener, err))
				s.up = false
			}
			s.delCloserNoLock(s.listener)
			return
		}

		s.info(newOpErr("new connection", conn, nil))
		s.regCloser(conn)

		go s.ServeClient(conn)
	}
}

// Running reports whether s is listening. 
func (s *Server) Running() bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.up
}

func (s *Server) Addr() net.Addr {
  s.mux.Lock()
  defer s.mux.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Close closes the internal listener. It's useful if you want to stop the [Server], 
// while wait for all remaining sessions to finish. 
// Returns [ErrNotStarted] if s is not started. 
// Connections established are not closed.
func (s *Server) Close() (err error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if !s.up {
		return ErrNotStarted
	}
	s.up = false
	s.info(newOpErr("server shut down", nil, nil))
	if err = s.listener.Close(); err != nil {
		s.warn(newOpErr("close listener", s.listener, err))
	}
	s.delCloserNoLock(s.listener)
  return
}

// CloseAll closes the internal listener and all established connections. 
// It's useful if you want to stop the [Server] and kill all sessions. 
//
// If s is not started, CloseAll closes established connections only. 
// If a connection or listener has failed to close,
// the [Server] won't try to close it next time.
func (s *Server) CloseAll() (errs []error){
	s.mux.Lock()
	defer s.mux.Unlock()
	s.up = false
	s.info(newOpErr("server shut down", nil, nil))
	for c := range s.closers {
		s.info(newOpErr("close "+closerType(c), c, nil))
		
		if err := c.Close(); err != nil {
      errs = append(errs, err)
			s.warn(err, newOpErr("close "+closerType(c), c, err))
		}
		s.delCloserNoLock(c)
	}
  return
}

func (s *Server) regCloser(c closer) {
	s.mux.Lock()
	defer s.mux.Unlock()
  if s.closers == nil {
    s.closers = map[closer]struct{}{}
  }
	s.closers[c] = struct{}{}
	s.dbgvv(newOpErr("reg closer", c, nil))
}

func (s *Server) regCloserNoLock(c closer) {
  if s.closers == nil {
    s.closers = map[closer]struct{}{}
  }
	s.closers[c] = struct{}{}
	s.dbgvv(newOpErr("reg closer without locking", c, nil))
}

func (s *Server) delCloser(c closer) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.closers, c)
	s.dbgvv(newOpErr("del closer", c, nil))
}

func (s *Server) delCloserNoLock(c closer) {
	delete(s.closers, c)
	s.dbgvv(newOpErr("del closer without locking", c, nil))
}

func (s *Server) closeCloser(c closer) error {
	if c == nil {
		return nil
	}
	s.info(newOpErr("close "+closerType(c), c, nil))
	err := c.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		s.warn(newOpErr("close "+closerType(c), c, err))
	}
	s.delCloser(c)
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
}

// ServeClient starts serving the client and blocks til finish.
// ServeClient can be invoked without s being started,
// this is useful if inbound connection listening need to be handled explicitly.
//
// Note that [Server.Close] and [Server.CloseAll] will still try to close
// connections created during serving, even if the server is not started.
func (s *Server) ServeClient(conn *net.TCPConn) {
	hs, err := readHandshake(conn)
	if err != nil {
		s.err(newOpErr("read handshake", conn, err))
		s.closeCloser(conn)
		return
	}
	hs.laddr = conn.LocalAddr()
	hs.raddr = conn.RemoteAddr()

	time.AfterFunc(PeriodAutoDeny, func() {
		hs.deny(true)
	})
	s.dbgv(newOpErr(
		fmt.Sprintf("select one method from % 02X", hs.methods),
		conn, nil,
	))
	sent := s.selectMethod(hs)

	if !sent || hs.timeoutDeny {
		s.warn(nil, newOpErr("serve", conn, &RequestNotHandledError{Type: "handshake", Timeout: hs.timeoutDeny}))
		s.closeCloser(conn)
		return
	}

	s.dbgv(newOpErr("selected method "+method2Str(hs.methodChosen), conn, nil))

	hsReply := []byte{VerSOCKS5, hs.methodChosen}
	if _, err := conn.Write(hsReply); err != nil {
		s.err(newOpErr("reply handshake", conn, err))
		s.closeCloser(conn)
		return
	}
	if hs.methodChosen == MethodNoAccepted {
		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(conn)
		})
		return
	}

	s.dbg(newOpErr(fmt.Sprintf("start subnegotiation %T", hs.neg), conn, nil))
	capper, err := hs.neg.Negotiate(conn)
	if err != nil {
		e := newOpErr("subnegotiate", conn, err)
		if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrMalformed) {
			s.warn(e)
		} else {
			s.err(e)
		}

		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(conn)
		})

		return
	}

	if capper == nil {
		capper = NoCap{}
	}
	s.dbgv(newOpErr(fmt.Sprintf("using capsulation %T", capper), conn, nil))

	req, err := readRequest(capper)
	if err != nil {
		s.err(newOpErr("read request", conn, err))
		s.closeCloser(conn)
		return
	}
  req.capper = capper

	s.dbg(newOpErr("received request "+cmd2str(req.cmd), conn, nil))
	s.dbgv(newOpErr("reply to request sent", conn, nil))

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
		s.warn(newOpErr("serve", conn, &CmdNotSupportedError{Cmd: req.cmd}))
	}

	if req.cmd != CmdCONNECT && req.cmd != CmdBIND && req.cmd != CmdASSOC {
		req.deny(RepCmdNotSupported, emptyAddr, false)
	} else {
		time.AfterFunc(PeriodAutoDeny, func() {
			req.deny(RepGeneralFailure, emptyAddr, true)
		})

		s.dbgv(newOpErr("evaluate request "+cmd2str(req.cmd), conn, nil))
		sent = s.evaluateRequest(wrappedReq)

		if sent {
			req.wg.Wait()
		} else {
			s.warn(newOpErr("serve", conn, &RequestNotHandledError{Type: cmd2str(req.cmd)}))
			req.deny(RepGeneralFailure, emptyAddr, false)
		}
	}
	if req.timeoutDeny {
		s.warn(newOpErr("serve", conn, &RequestNotHandledError{Type: cmd2str(req.cmd), Timeout: true}))
	}

	s.dbg(newOpErr(fmt.Sprintf("reply %s to request %s", rep2str(req.reply.rep), cmd2str(req.cmd)), conn, nil))

	raw, _ := req.reply.MarshalBinary()
	if _, err := capper.Write(raw); err != nil {
		s.err(newOpErr("reply request", conn, err))
		s.closeCloser(conn)
		return
	}

	if req.reply.rep != RepSucceeded {
		s.dbg(newOpErr(fmt.Sprintf("reply %s to request %s", rep2str(req.reply.rep), cmd2str(req.cmd)), conn, nil))
	}

	switch req.cmd {
	case CmdCONNECT:
		s.handleConnect(wrappedReq.(*ConnectRequest), capper, conn)
	case CmdBIND:
		s.handleBind(wrappedReq.(*BindRequest), capper, conn)
	case CmdASSOC:
		s.handleAssoc(wrappedReq.(*AssocRequest), conn)
	}
}

func (s *Server) handleConnect(r *ConnectRequest, capper Capsulator, conn net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(r.conn)
			s.closeCloser(conn)
		})
		return
	}

	s.regCloser(r.conn)

	s.info(newOpErr("relay CONNECT started "+relay2str(conn, r.conn), nil, nil))

	go s.relay(capper, r.conn, func(err error) {
		if err != nil {
			s.err(newOpErr("relay CONNECT "+relay2str(conn, r.conn), nil, err))
		} else {
			s.info(newOpErr("relay CONNECT "+relay2str(conn, r.conn)+" EOF", nil, err))
		}
	})
}

func (s *Server) handleBind(r *BindRequest, capper Capsulator, conn net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			s.closeCloser(r.conn)
		})
		return
	}

	time.AfterFunc(PeriodAutoDeny, func() {
		r.denyBind(RepGeneralFailure, emptyAddr, true)
	})
	r.bindWg.Wait()

	if r.bindTimeoutDeny {
		s.warn(newOpErr("serve", conn, &RequestNotHandledError{Type: cmd2str(CmdBIND), Timeout: true}))
	}

	s.dbg(newOpErr(fmt.Sprintf("reply %s to request BND(2nd)", rep2str(r.bindReply.rep)), conn, nil))
	raw, _ := r.bindReply.MarshalBinary()
	if _, err := capper.Write(raw); err != nil {
		s.err(newOpErr("reply BND(2nd)", conn, err))
		s.closeCloser(conn)
		return
	}

	s.info(newOpErr("relay BND started "+relay2str(conn, r.conn), nil, nil))

	go s.relay(capper, r.conn, func(err error) {
		if err != nil {
			s.err(newOpErr("relay BND  "+relay2str(conn, r.conn), nil, err))
		} else {
			s.info(newOpErr("relay BND  "+relay2str(conn, r.conn)+" EOF", nil, err))
		}
	})
}

func (s *Server) handleAssoc(r *AssocRequest, conn net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			r.terminate()
			s.closeCloser(conn)
		})
    return
	}

  _, err := io.Copy(io.Discard, conn)
  r.notifyOnce.Do(func() {
    if r.notify == nil {
      return
    }
    if err == nil {
      err = io.EOF
    }
    r.notify(err)
  })
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

func (s *Server) relay(a, b io.ReadWriter, onErr func(error)) {
	once := sync.Once{}

	cpy := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		once.Do(func() {
			onErr(err)
		})
	}

	go cpy(a, b)
	go cpy(b, a)
}
