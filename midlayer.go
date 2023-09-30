// # Description
//
// Package socksy5 provides a SOCKS5 middle layer
// and utils for simple request handling.
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
// they only have basic features. You can handle handshakes and requests yourself
// if they don't meet your requirement.
//
// # How to use
//
// First pass a [net.Conn] to a [MidLayer] instance,
// then [MidLayer] will begin communicating with the client.
// When client begins handshakes or sends requests, [MidLayer] will emit
// [Handshake], [ConnectRequest], [BindRequest] and [AssocRequest] via channels.
// Call methods of them to decide which kind of authentication to use,
// whether accept or reject and so on.
// Logs are emitted via channels too.
// See [MidLayer.LogChan], [MidLayer.HandshakeChan], [MidLayer.RequestChan].
// User of this package should read [Request], as it contains general info about
// different types of requests.
//
// # Note
//
// socksy5 provides limited implementations of authenticate methods,
// for quite a long time.
// [MidLayer] does relay TCP traffic, but it doesn't dial outbound or
// relay UDP traffic.
package socksy5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Constants of [MidLayer] policy.
const (
	// Channel capacity of all channels returned by MidLayer's channel methods.
	ChanCap = 64
	// Time to close connection if auth failed, request denied, e.t.c..
	PeriodClose = time.Second * time.Duration(3)
	// Time to wait for external code to react to handshakes and requests.
	PeriodAutoDeny = time.Second * time.Duration(30)
)

// A MidLayer is a SOCKS5 middle layer. See package description for detail.
//
// All methods of MidLayer can be called simultaineously.
type MidLayer struct {
	mux         sync.Mutex
	logChan     chan LogEntry
	hndshkChan  chan *Handshake
	requestChan chan any
	conns       map[net.Conn]struct{}
}

// Close closes all established connections.
// It's useful if you want to kill all sessions.
//
// If a connection has failed to close,
// ml won't try to close it next time.
// errs contain errors returned by [net.Conn.Close].
func (ml *MidLayer) Close() (errs []error) {
	ml.mux.Lock()
	defer ml.mux.Unlock()
	ml.info(newOpErr("closing all connections", nil, nil))
	for c := range ml.conns {
		ml.info(newOpErr("connection close", c, nil))

		if err := c.Close(); err != nil {
			errs = append(errs, err)
			ml.warn(err, newOpErr("close connection", c, err))
		}
		ml.delConnNoLock(c)
	}
	return
}

func (ml *MidLayer) regConn(c net.Conn) {
	ml.mux.Lock()
	defer ml.mux.Unlock()
	ml.regConnNoLock(c)
	return
}

func (ml *MidLayer) regConnNoLock(c net.Conn) {
	if ml.conns == nil {
		ml.conns = make(map[net.Conn]struct{})
	}
	ml.conns[c] = struct{}{}
	ml.dbgvv(newOpErr("register connection", c, nil))
	return
}

func (ml *MidLayer) delConn(c net.Conn) {
	ml.mux.Lock()
	defer ml.mux.Unlock()
	ml.delConnNoLock(c)
}

func (ml *MidLayer) delConnNoLock(c net.Conn) {
	if _, ok := ml.conns[c]; !ok {
		ml.err(newOpErr("deregistering not registered connection, report this bug", c, nil))
		return
	}
	delete(ml.conns, c)
	ml.dbgvv(newOpErr("deregister connection", c, nil))
}

func (ml *MidLayer) closeConn(c net.Conn) error {
	if c == nil {
		return nil
	}
	ml.info(newOpErr("connection close", c, nil))
	err := c.Close()
	if err != nil {
		ml.warn(newOpErr("close connection", c, err))
	}
	ml.delConn(c)
	return err
}

// All channel methods create a corresponding channel if not ever created.
// If no channel is created or the channel is full, corresponding log entries are
// discarded.
func (ml *MidLayer) LogChan() <-chan LogEntry {
	ml.mux.Lock()
	defer ml.mux.Unlock()
	if ml.logChan == nil {
		ml.logChan = make(chan LogEntry, ChanCap)
	}
	return ml.logChan
}

// All channel methods create a corresponding channel if not ever created.
// If no channel is created or the channel is full, corresponding handshakes are
// rejected by closing connection, instead of sending a reply.
func (ml *MidLayer) HandshakeChan() <-chan *Handshake {
	ml.mux.Lock()
	defer ml.mux.Unlock()
	if ml.hndshkChan == nil {
		ml.hndshkChan = make(chan *Handshake, ChanCap)
	}
	return ml.hndshkChan
}

// RequestChan is guaranteed to return a channel that receives one of
// types [*ConnectRequest], [*BindRequest] and [*AssocRequest].
//
// All channel methods create a corresponding channel if not ever created.
// If no channel is created or the channel is full, corresponding requests are
// rejected with [RepGeneralFailure].
func (ml *MidLayer) RequestChan() <-chan any {
	ml.mux.Lock()
	defer ml.mux.Unlock()
	if ml.requestChan == nil {
		ml.requestChan = make(chan any, ChanCap)
	}
	return (<-chan any)(ml.requestChan)
}

// ServeClient starts serving the client and blocks til finish.
//
// Note that if the client sends CONNECT or BIND request, even if the request is
// accepted and the TCP traffic relaying is successful
// (one of the connections closed normally),
// a [RelayError] is still returned.
func (ml *MidLayer) ServeClient(conn net.Conn) error { // TODO Check compability with net.Conn (nil addr etc)
	ml.info(newOpErr("new connection", conn, nil))
	hs, rerr := readHandshake(conn)
	if rerr != nil {
		rerr = newOpErr("read handshake", conn, rerr)
		ml.err(rerr)
		if cerr := conn.Close(); cerr != nil {
			ml.err(newOpErr("close connection", conn, cerr))
		}
		return rerr
	}
	hs.laddr = conn.LocalAddr()
	hs.raddr = conn.RemoteAddr()
	ml.regConn(conn)
	uuid := uuid.New()
	ml.dbg(newOpErr("assigned session with UUID"+uuid.String(), conn, nil))
	hs.uuid = uuid

	time.AfterFunc(PeriodAutoDeny, func() {
		hs.deny(true)
	})
	ml.dbgv(newOpErr(
		fmt.Sprintf("select one method from % 02X", hs.methods),
		conn, nil,
	))
	sent := ml.selectMethod(hs)

	if !sent || hs.timeoutDeny {
		err := newOpErr("serve", conn, &RequestNotHandledError{Type: "handshake", Timeout: hs.timeoutDeny})
		ml.warn(nil, err)
		ml.closeConn(conn)
		return err
	}

	ml.dbgv(newOpErr("selected method "+method2Str(hs.methodChosen), conn, nil))

	hsReply := []byte{VerSOCKS5, hs.methodChosen}
	if _, werr := conn.Write(hsReply); werr != nil {
		err := newOpErr("reply handshake", conn, werr)
		ml.err(err)
		ml.closeConn(conn)
		return err
	}
	if hs.methodChosen == MethodNoAccepted {
		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(conn)
		})
		return nil
	}

	ml.dbg(newOpErr("start subnegotiation "+hs.neg.Type(), conn, nil))
	capper, rerr := hs.neg.Negotiate(conn)
	if rerr != nil {
		err := newOpErr("subnegotiate", conn, rerr)
		if errors.Is(rerr, ErrAuthFailed) || errors.Is(rerr, ErrMalformed) {
			ml.warn(err)
		} else {
			ml.err(err)
		}

		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(conn)
		})

		return err
	}

	if capper == nil {
		capper = NoCap{}
	}
	ml.dbgv(newOpErr(fmt.Sprintf("using capsulation %T", capper), conn, nil))

	req, rerr := readRequest(capper)
	if rerr != nil {
		err := newOpErr("read request", conn, rerr)
		ml.err(err)
		ml.closeConn(conn)
		return err
	}

	ml.dbg(newOpErr("received request "+cmd2str(req.cmd), conn, nil))

	req.capper = capper
	req.uuid = uuid
	req.laddr = conn.LocalAddr()
	req.raddr = conn.RemoteAddr()

	// Code below is kind of messy I know, because they are sorta workarounds.
	// req needs to be re-assigned here, because it will be value-copied. see below
	var wrappedReq any // One of *ConnectRequest, *BindRequest, *AssocRequest
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
		br.reply = nil // BindRequest.Bind relies on this to check if it's accepted
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
			return ml.closeConn(conn)
		}
		ar.terminate = terminator
		wrappedReq = ar
		req = &ar.Request
		req.dst.Protocol = "udp"
	default:
		err := newOpErr("serve", conn, CmdNotSupportedError(req.cmd))
		ml.warn(err)
		req.deny(RepCmdNotSupported, emptyAddr, false)
		raw, _ := req.reply.MarshalBinary()
		if _, werr := capper.Write(raw); werr != nil {
			ml.err(newOpErr("reply request", conn, werr))
			ml.closeConn(conn)
		} else {
			time.AfterFunc(PeriodClose, func() {
				ml.closeConn(conn)
			})
		}
		return err
	}

	ml.dbgv(newOpErr("evaluate request "+cmd2str(req.cmd), conn, nil))
	sent = ml.evaluateRequest(wrappedReq, req)

	var unhandledErr error
	if !sent || req.timeoutDeny {
		unhandledErr = &RequestNotHandledError{Type: cmd2str(req.cmd), Timeout: req.timeoutDeny}
		ml.warn(newOpErr("serve", conn, unhandledErr))
	}

	ml.dbg(newOpErr(fmt.Sprintf("reply %s to request %s", rep2str(req.reply.code), cmd2str(req.cmd)), conn, nil))

	raw, _ := req.reply.MarshalBinary()
	_, werr := capper.Write(raw)
	if werr != nil {
		ml.err(newOpErr("reply request", conn, werr))
		if unhandledErr != nil {
			return unhandledErr
		}
		return rerr
	}

	if req.reply.code != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(conn)
		})
		return unhandledErr
	}

	switch req.cmd {
	case CmdCONNECT:
		return ml.handleConnect(wrappedReq.(*ConnectRequest), capper, conn)
	case CmdBIND:
		return ml.handleBind(wrappedReq.(*BindRequest), capper, conn)
	case CmdASSOC:
		return ml.handleAssoc(wrappedReq.(*AssocRequest), conn)
	}
	return errors.New("I don't think it should happen, right? In case it really did, BUG CODE 0x2A!")
}

func (ml *MidLayer) handleConnect(r *ConnectRequest, capper Capsulator, inbound net.Conn) error {
	ml.regConn(r.outbound)

	ml.info(newOpErr("relay CONNECT started "+relay2str(inbound, r.outbound), nil, nil))

	return ml.relay(capper, inbound, r.outbound)
}

func (ml *MidLayer) handleBind(r *BindRequest, capper Capsulator, clientConn net.Conn) error {
	r.bindWg.Wait()

	bound := r.bindReply.code == RepSucceeded
	if bound {
		ml.regConn(r.hostConn)
	}

	ml.dbg(newOpErr(fmt.Sprintf("reply %s to request BND(2nd reply)", rep2str(r.bindReply.code)), clientConn, nil))
	raw, _ := r.bindReply.MarshalBinary()
	if _, err := capper.Write(raw); err != nil {
		ml.err(newOpErr("reply BND(2nd)", clientConn, err))
		ml.closeConn(clientConn)
		ml.closeConn(r.hostConn)
		return err
	}

	if bound {
		ml.info(newOpErr("relay BND started "+relay2str(clientConn, r.hostConn), nil, nil))
		return ml.relay(capper, clientConn, r.hostConn)
	}
	return nil
}

func (ml *MidLayer) handleAssoc(r *AssocRequest, inbound net.Conn) error {
	_, err := io.Copy(io.Discard, inbound)
	r.notifyOnce.Do(func() {
		if err == nil {
			err = io.EOF
		}
		r.finalErr = err
		if r.notify == nil {
			return
		}
		go r.notify(err)
	})
	return r.finalErr
}

func (ml *MidLayer) selectMethod(hs *Handshake) (sent bool) {
	hs.wg.Add(1)
	ml.mux.Lock()
	if ml.hndshkChan != nil {
		ml.mux.Unlock()
		select {
		case ml.hndshkChan <- hs:
			sent = true
			hs.wg.Wait()
		default:
		}
	} else {
		ml.mux.Unlock()
	}
	return
}

func (ml *MidLayer) evaluateRequest(wrapped any, inner *Request) (sent bool) {
	inner.wg.Add(1)
	ml.mux.Lock()
	select {
	case ml.requestChan <- wrapped:
		ml.mux.Unlock()
		sent = true
		time.AfterFunc(PeriodAutoDeny, func() {
			inner.deny(RepGeneralFailure, emptyAddr, true)
		})
		inner.wg.Wait()
	default:
		ml.mux.Unlock()
		inner.deny(RepGeneralFailure, emptyAddr, false)
	}
	return
}

func (ml *MidLayer) relay(capper Capsulator, clientConn, hostConn net.Conn) *RelayError {
	var chErr error
	var hcErr error
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		_, hcErr = io.Copy(capper, hostConn)
		wg.Done()
	}()
	go func() {
		_, chErr = io.Copy(hostConn, capper)
		wg.Done()
	}()
	wg.Wait()

	if chErr == nil {
		chErr = io.EOF
	}
	if hcErr == nil {
		hcErr = io.EOF
	}

	ml.closeConn(clientConn)
	ml.closeConn(hostConn)

	// I know that even if one of the 2 conns closed normally, MidLayer will still
	// complain about it...But I have no better idea for now.
	err := newRelayErr(clientConn, hostConn, chErr, hcErr)
	ml.err(err)
	return err
}
