// # Description
// 
// Package socksy5 provides a SOCKS5 middle layer 
// and utils for easy request handling. 
// [MidLayer] implements the middle layer, which accepts client connections 
// in the form of [net.Conn] (see [MidLayer.ServeClient]), 
// then wraps client handshakes and requests as structs, 
// letting external code to decide whether accept or reject, which kind of 
// subnegotiation to use e.t.c.. 
//
// This provides advantages when you need multi-homed BND or UDP ASSOCIATION
// processing, custom subnegotiation and encryption, attaching special 
// connection to CONNECT requests. 
//
// Besides that, socksy5 also provides [Connect], [Binder] and [Associator] 
// as simple handlers for CONNECT, BND and UDP ASSOC requests. 
// [Listen] is also provided as a simple listening util which passes [net.Conn] 
// to [MidLayer] automatically. 
// They are for ease of use if you want to set up a SOCKS5 server fast, thus 
// only have basic features. You can handle handshakes and requests yourself 
// if they don't meet your requirement. 
//
// # How to use
//
// First pass a [net.Conn] to a [MidLayer] instance, 
// then [MidLayer] will begin communicating with the client. 
// When client begins handshakes or sends requests, [MidLayer] will emit 
// [Handshake], [ConnectRequest], [BindRequest] and [AssocRequest] via channels. 
// Invoke methods of them to decide which kind of authentication to use, 
// whether accept or reject and so on. 
// Logs are emitted via channels too. 
// See [MidLayer.LogChan], [MidLayer.HandshakeChan], [MidLayer.RequestChan]. 
//
// # Limitations
//
// [MidLayer] is just a middle layer. It doesn't dial outbound connections, 
// relay TCP connection for BIND requests, nor relay UDP packets. 
//
// Also, socksy5 provides limited implementations of authenticate methods, 
// for quite a long time. 
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
	// Channel capacity of all channels returned by MidLayer's channel methods.
	ChanCap = 64
	// Time to close connection if auth failed, request denied, e.t.c..
	PeriodClose    = time.Second * time.Duration(3)
  // Time to wait for external code to react to handshakes and requests. 
	PeriodAutoDeny = time.Second * time.Duration(30)
)

// A MidLayer is a SOCKS5 middle layer. See package description for detail. 
//
// Use channel methods (e.g. [MidLayer.HandshakeChan]) to deal with logging, requests e.t.c..
type MidLayer struct {
	mux         sync.Mutex
	logChan     chan LogEntry
	hndshkChan  chan *Handshake
	requestChan chan any
	closers     map[closer]struct{}
}

// Close closes all established connections.
// It's useful if you want to kill all sessions.
//
// If a connection has failed to close,
// the [MidLayer] won't try to close it next time.
func (s *MidLayer) Close() (errs []error) {
	s.mux.Lock()
	defer s.mux.Unlock()
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

func (s *MidLayer) regCloser(c closer) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.closers == nil {
		s.closers = map[closer]struct{}{}
	}
	s.closers[c] = struct{}{}
	s.dbgvv(newOpErr("reg closer", c, nil))
}

func (s *MidLayer) regCloserNoLock(c closer) {
	if s.closers == nil {
		s.closers = map[closer]struct{}{}
	}
	s.closers[c] = struct{}{}
	s.dbgvv(newOpErr("reg closer without locking", c, nil))
}

func (s *MidLayer) delCloser(c closer) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.closers, c)
	s.dbgvv(newOpErr("del closer", c, nil))
}

func (s *MidLayer) delCloserNoLock(c closer) {
	delete(s.closers, c)
	s.dbgvv(newOpErr("del closer without locking", c, nil))
}

func (s *MidLayer) closeCloser(c closer) error {
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

// All channel methods create a corresponding channel if not ever created.
// If no channel is created or the channel is full, corresponding log entries are
// discarded. 
func (s *MidLayer) LogChan() <-chan LogEntry {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.logChan == nil {
		s.logChan = make(chan LogEntry, ChanCap)
	}
	return (<-chan LogEntry)(s.logChan)
}

// All channel methods create a corresponding channel if not ever created.
// If no channel is created or the channel is full, corresponding handshakes are
// rejected by closing connection, instead of sending a reply. 
func (s *MidLayer) HandshakeChan() <-chan *Handshake {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.hndshkChan == nil {
		s.hndshkChan = make(chan *Handshake, ChanCap)
	}
	return (<-chan *Handshake)(s.hndshkChan)
}

// RequestChan is guaranteed to return a channel that receives one of
// types [*ConnectRequest], [*BindRequest] and [*AssocRequest].
//
// All channel methods create a corresponding channel if not ever created.
// If no channel is created or the channel is full, corresponding requests are
// rejected with [RepGeneralFailure]. 
func (s *MidLayer) RequestChan() <-chan any {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.requestChan == nil {
		s.requestChan = make(chan any, ChanCap)
	}
	return (<-chan any)(s.requestChan)
}

func (s *MidLayer) listen() {
}

// ServeClient starts serving the client and blocks til finish.
// ServeClient can be invoked without s being started,
// this is useful if inbound connection listening need to be handled explicitly.
//
// Note that [MidLayer.Close] and [MidLayer.CloseAll] will still try to close
// connections created during serving, even if the server is not started.
func (s *MidLayer) ServeClient(conn net.Conn) { // TODO Check compability with net.Conn (nil addr etc)
  s.info(newOpErr("new connection", conn, nil))
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
		req.dst.Protocol = "tcp"
	case CmdBIND:
		br := &BindRequest{
			Request: *req,
		}
		br.reply = nil // Bind() relies on this to check if it's accepted
		br.bindWg.Add(1)
		wrappedReq = br
		req = &br.Request
		req.dst.Protocol = "tcp"
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
		req.dst.Protocol = "udp"
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

func (s *MidLayer) handleConnect(r *ConnectRequest, capper Capsulator, conn net.Conn) {
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

func (s *MidLayer) handleBind(r *BindRequest, capper Capsulator, conn net.Conn) {
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

func (s *MidLayer) handleAssoc(r *AssocRequest, conn net.Conn) {
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

func (s *MidLayer) selectMethod(hs *Handshake) (sent bool) {
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

func (s *MidLayer) evaluateRequest(r any) (sent bool) {
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

func (s *MidLayer) relay(a, b io.ReadWriter, onErr func(error)) {
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
