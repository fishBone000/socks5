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

	"github.com/google/uuid"
)

// Constants for server policy.
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
// Use channel methods (e.g. [MidLayer.HandshakeChan]) to deal with logging, requests e.t.c..
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
// the [MidLayer] won't try to close it next time.
func (ml *MidLayer) Close() (errs []error) {
	ml.mux.Lock()
	defer ml.mux.Unlock()
	ml.info(newOpErr("server shut down", nil, nil))
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
	return (<-chan LogEntry)(ml.logChan)
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
	return (<-chan *Handshake)(ml.hndshkChan)
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

func (ml *MidLayer) listen() {
}

// ServeClient starts serving the client and blocks til finish.
// ServeClient can be invoked without s being started,
// this is useful if inbound connection listening need to be handled explicitly.
//
// Note that [MidLayer.Close] and [MidLayer.CloseAll] will still try to close
// connections created during serving, even if the server is not started.
func (ml *MidLayer) ServeClient(conn net.Conn) { // TODO Check compability with net.Conn (nil addr etc)
	ml.info(newOpErr("new connection", conn, nil))
	hs, err := readHandshake(conn)
	if err != nil {
		ml.err(newOpErr("read handshake", conn, err))
		if err := conn.Close(); err != nil {
			ml.err(newOpErr("close connection", conn, err))
		}
		return
	}
	hs.laddr = conn.LocalAddr()
	hs.raddr = conn.RemoteAddr()
	ml.regConn(conn)
	uuid := uuid.New()
	ml.dbg(newOpErr("assigned session with UUID %s"+uuid.String(), conn, nil))
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
		ml.warn(nil, newOpErr("serve", conn, &RequestNotHandledError{Type: "handshake", Timeout: hs.timeoutDeny}))
		ml.closeConn(conn)
		return
	}

	ml.dbgv(newOpErr("selected method "+method2Str(hs.methodChosen), conn, nil))

	hsReply := []byte{VerSOCKS5, hs.methodChosen}
	if _, err := conn.Write(hsReply); err != nil {
		ml.err(newOpErr("reply handshake", conn, err))
		ml.closeConn(conn)
		return
	}
	if hs.methodChosen == MethodNoAccepted {
		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(conn)
		})
		return
	}

	ml.dbg(newOpErr("start subnegotiation "+hs.neg.Type(), conn, nil))
	capper, err := hs.neg.Negotiate(conn)
	if err != nil {
		e := newOpErr("subnegotiate", conn, err)
		if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrMalformed) {
			ml.warn(e)
		} else {
			ml.err(e)
		}

		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(conn)
		})

		return
	}

	if capper == nil {
		capper = NoCap{}
	}
	ml.dbgv(newOpErr(fmt.Sprintf("using capsulation %T", capper), conn, nil))

	req, err := readRequest(capper)
	if err != nil {
		ml.err(newOpErr("read request", conn, err))
		ml.closeConn(conn)
		return
	}
	req.capper = capper
	req.uuid = uuid

	ml.dbg(newOpErr("received request "+cmd2str(req.cmd), conn, nil))
	ml.dbgv(newOpErr("reply to request sent", conn, nil))

	req.laddr = conn.LocalAddr()
	req.raddr = conn.RemoteAddr()
	req.wg.Add(1)

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
		ml.warn(newOpErr("serve", conn, &CmdNotSupportedError{Cmd: req.cmd}))
		req.deny(RepCmdNotSupported, emptyAddr, false)
		raw, _ := req.reply.MarshalBinary()
		if _, err := capper.Write(raw); err != nil {
			ml.err(newOpErr("reply request", conn, err))
			ml.closeConn(conn)
		}
		return
	}

	time.AfterFunc(PeriodAutoDeny, func() {
		req.deny(RepGeneralFailure, emptyAddr, true)
	})

	ml.dbgv(newOpErr("evaluate request "+cmd2str(req.cmd), conn, nil))
	sent = ml.evaluateRequest(wrappedReq)

	if sent {
		req.wg.Wait()
	} else {
		ml.warn(newOpErr("serve", conn, &RequestNotHandledError{Type: cmd2str(req.cmd)}))
		req.deny(RepGeneralFailure, emptyAddr, false)
	}

	if req.timeoutDeny {
		ml.warn(newOpErr("serve", conn, &RequestNotHandledError{Type: cmd2str(req.cmd), Timeout: true}))
	}

	ml.dbg(newOpErr(fmt.Sprintf("reply %s to request %s", rep2str(req.reply.rep), cmd2str(req.cmd)), conn, nil))

	raw, _ := req.reply.MarshalBinary()
	if _, err := capper.Write(raw); err != nil {
		ml.err(newOpErr("reply request", conn, err))
		ml.closeConn(conn)
		return
	}

	if req.reply.rep != RepSucceeded {
		ml.dbg(newOpErr(fmt.Sprintf("reply %s to request %s", rep2str(req.reply.rep), cmd2str(req.cmd)), conn, nil))
	}

	switch req.cmd {
	case CmdCONNECT:
		ml.handleConnect(wrappedReq.(*ConnectRequest), capper, conn)
	case CmdBIND:
		ml.handleBind(wrappedReq.(*BindRequest), capper, conn)
	case CmdASSOC:
		ml.handleAssoc(wrappedReq.(*AssocRequest), conn)
	}
}

func (ml *MidLayer) handleConnect(r *ConnectRequest, capper Capsulator, inbound net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(inbound)
		})
		return
	}

	ml.regConn(r.outbound)

	ml.info(newOpErr("relay CONNECT started "+relay2str(inbound, r.outbound), nil, nil))

	ml.relay(capper, inbound, r.outbound)
}

func (ml *MidLayer) handleBind(r *BindRequest, capper Capsulator, inbound net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(r.hostConn)
		})
		return
	}

	time.AfterFunc(PeriodAutoDeny, func() {
		r.denyBind(RepGeneralFailure, emptyAddr, true)
	})
	r.bindWg.Wait()

	if r.bindTimeoutDeny {
		ml.warn(newOpErr("serve", inbound, &RequestNotHandledError{Type: cmd2str(CmdBIND), Timeout: true}))
	}

	bound := r.bindReply.rep == RepSucceeded
	if bound {
		ml.regConn(r.hostConn)
	}

	ml.dbg(newOpErr(fmt.Sprintf("reply %s to request BND(2nd)", rep2str(r.bindReply.rep)), inbound, nil))
	raw, _ := r.bindReply.MarshalBinary()
	if _, err := capper.Write(raw); err != nil {
		ml.err(newOpErr("reply BND(2nd)", inbound, err))
		ml.closeConn(inbound)
		ml.closeConn(r.hostConn)
		return
	}

	if bound {
		ml.info(newOpErr("relay BND started "+relay2str(inbound, r.hostConn), nil, nil))
		ml.relay(capper, inbound, r.hostConn)
	}
}

func (ml *MidLayer) handleAssoc(r *AssocRequest, inbound net.Conn) {
	if r.reply.rep != RepSucceeded {
		time.AfterFunc(PeriodClose, func() {
			ml.closeConn(inbound)
		})
		return
	}

	_, err := io.Copy(io.Discard, inbound)
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

func (ml *MidLayer) evaluateRequest(r any) (sent bool) {
	ml.mux.Lock()
	if ml.requestChan != nil {
		ml.mux.Unlock()
		select {
		case ml.requestChan <- r:
			sent = true
		default:
		}
	} else {
		ml.mux.Unlock()
	}
	return
}

func (ml *MidLayer) relay(capper Capsulator, clientConn, hostConn net.Conn) {
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

	if chErr == nil && errors.Is(hcErr, net.ErrClosed) {
		msg := fmt.Sprintf("relay client %s and host %s: client EOF", clientConn.RemoteAddr(), hostConn.RemoteAddr())
		ml.info(newOpErr(msg, nil, nil))
		ml.delConn(clientConn)
		ml.closeConn(hostConn)
	} else if hcErr == nil && errors.Is(chErr, net.ErrClosed) {
		msg := fmt.Sprintf("relay client %s and host %s: host EOF", clientConn.RemoteAddr(), hostConn.RemoteAddr())
		ml.info(newOpErr(msg, nil, nil))
		ml.delConn(hostConn)
		ml.closeConn(clientConn)
	} else {
		if chErr == nil {
			chErr = io.EOF
		}
		if hcErr == nil {
			hcErr = io.EOF
		}
		msg := fmt.Sprintf("relay from client %s to host %s", clientConn.RemoteAddr(), hostConn.RemoteAddr())
		ml.err(newOpErr(msg, nil, chErr))
		msg = fmt.Sprintf("relay from host %s to client %s", hostConn.RemoteAddr(), clientConn.RemoteAddr())
		ml.err(newOpErr(msg, nil, hcErr))
		ml.closeConn(clientConn)
		ml.closeConn(hostConn)
	}
}
