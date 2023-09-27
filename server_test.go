package socksy5

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TODO test closer reg
// TODO test auto deny
// TODO test chan discarding
// TODO test parsing from string to Addr

// Is this sim test really useful? 
// It has 900 lines of code, yet sim test bugs : Server bugs = 5 : 1
// Plus I need to edit this each time I change any stuff in Server...

const (
	timeoutRcv    = 100 * time.Millisecond
)

func TestSimulation(t *testing.T) {
	mngr := testMngr{}

	mngr.run(30*time.Minute, 100*time.Millisecond, t)

	t.Logf("finished, %d testers run", mngr.nTests)
}

// ||||| Utils used in simulation test |||||
// VVVVV                               VVVVV

type malform struct {
	hsVer  bool
	reqVer bool
	cmd    bool
	rsv    bool
	atyp   bool
}

func newMalform() malform {
	malf := malform{}
	if rand.Intn(100) <= 95 {
		return malf
	}

	switch rand.Intn(5) {
	case 0:
		malf.hsVer = true
	case 1:
		malf.reqVer = true
	case 2:
		malf.cmd = true
	case 3:
		malf.rsv = true
	case 4:
		malf.atyp = true
	}
	return malf
}

func (m *malform) String() string {
	return fmt.Sprintf("VER(HS) %t, VER(REQ) %t, CMD %t, RSV %t, ATYP %t",
		m.hsVer, m.reqVer, m.cmd, m.rsv, m.atyp)
}

func (m *malform) shouldFailHandshake() bool {
	return m.hsVer
}

func (m *malform) shouldFailRequest() bool {
	return m.reqVer || m.cmd || m.rsv || m.atyp
}

type testMngr struct {
	// Fill these fields in before running
	s *Server
	t *testing.T

	mux     sync.Mutex
	stop    chan struct{}
  quit chan struct{}
	testers map[uint16]*tester
	nTests  int
}

func (m *testMngr) regTester(t *tester) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.testers[t.port] = t
	m.nTests++
}

func (m *testMngr) delTester(t *tester) {
	m.mux.Lock()
	defer m.mux.Unlock()
	delete(m.testers, t.port)
}

func (m *testMngr) run(testTime, interval time.Duration, t *testing.T) {
	m.t = t

	m.s = &Server{}
  waitStart := sync.WaitGroup{}
  waitStart.Add(1)
	go m.dispatch()
  go func()  {
    waitStart.Done()
    if err := m.s.Serve("localhost:4000"); err != nil {
      panic("serve failed: "+err.Error())
    }
  }()

	m.stop = make(chan struct{})
	m.quit = make(chan struct{})
	m.testers = map[uint16]*tester{}
	var stopT time.Time
	time.AfterFunc(testTime, func() {
		stopT = time.Now()
		close(m.stop)
	})

	prevTestTime := time.Time{}

  waitStart.Wait()
  time.Sleep(50 * time.Millisecond)
	for {
		select {
		case <-m.stop:
			m.waitFinish(stopT)
      close(m.quit)
			return
		default:
			if m.t.Failed() {
				// Wait outputting all remaining logs
				time.Sleep(100 * time.Millisecond)
        close(m.quit)
				return
			}

			if time.Now().Sub(prevTestTime) > interval {
				prevTestTime = time.Now()
				tester := newTester()
				go tester.start(m)
			}
		}
	}
}

func (m *testMngr) dispatch() {
	logChan := m.s.LogChan()
	reqChan := m.s.RequestChan()
	hsChan := m.s.HandshakeChan()

Loop:
	for {
		select {
		case log := <-logChan:
			m.dispatchLog(&log)
		case req := <-reqChan:
			go m.dispatchReq(req)
		case hs := <-hsChan:
			go m.dispatchHandshake(hs)
		case <-m.quit:
			break Loop
		}
	}
}

func (m *testMngr) getTester(addr string) *tester {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		m.t.Logf("get tester at %s: %s", addr, err)
		m.t.Fail()
		return nil
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	port, err := strconv.Atoi(portStr)
	if err != nil {
		m.t.Logf("get tester at %s: %s", addr, err)
		m.t.Fail()
		return nil
	}
	if port < 1 || port > 0xFFFF {
		m.t.Logf("port of the tester at %s is invalid", addr)
		m.t.Fail()
		return nil
	}

	t := m.testers[uint16(port)]
	return t
}

func (m *testMngr) dispatchHandshake(hs *Handshake) {
	var tester *tester
	tester = m.getTester(hs.RemoteAddr().String())
	if tester == nil {
		return
	}

	tester.hsChan <- hs
}

func (m *testMngr) dispatchLog(log *LogEntry) {
	// We only want OpError at SeverityError
	if _, ok := log.Err.(*OpError); log.Severity != SeverityError || !ok {
		m.t.Log(log.String())
		return
	}

	opErr := log.Err.(*OpError)
	addr := opErr.RemoteAddr
	if addr == nil {
		m.t.Log(log.String())
		return
	}

	var tester *tester
	tester = m.getTester(addr.String())
	if tester == nil {
		m.t.Logf("couldn't dispatch the following log entry vvv")
		m.t.Log(log.String())
		return
	}

	tester.mux.Lock()
	defer tester.mux.Unlock()

	select {
	case tester.errChan <- opErr:
	default:
		m.t.Logf("dispatch err to tester %s failed", tester.conn.LocalAddr())
		m.t.Logf("err to be dispatched: %s", opErr)
		m.t.Logf("tester detail: \n%s\n", tester.String())
		m.t.Fail()
	}
}

func (m *testMngr) dispatchReq(req any) {
	var addr net.Addr

	switch req := req.(type) {
	case *ConnectRequest:
		addr = req.RemoteAddr()
	case *BindRequest:
		addr = req.RemoteAddr()
	case *AssocRequest:
		addr = req.RemoteAddr()
	default:
		m.t.Logf("request %#v is of unknown type", req)
		m.t.Fail()
		return
	}

	var tester *tester
	tester = m.getTester(addr.String())
	if tester == nil {
		return
	}

	tester.reqChan <- req
}

func (m *testMngr) waitFinish(stopT time.Time) {
	elasped := time.Now().Sub(stopT)
	for ; elasped.Seconds() < 10*time.Second.Seconds(); elasped = time.Now().Sub(stopT) {
		if len(m.testers) == 0 || m.t.Failed() {
			return
		}
	}
	m.t.Fail()

	m.mux.Lock()
	defer m.mux.Unlock()
	m.t.Log("timed out waiting for testers to finish")
	m.t.Log("total tests:", m.nTests)
	m.t.Logf("%d testers are still running:\n", len(m.testers))
	for _, tester := range m.testers {
		m.t.Log(tester.String() + "\n")
	}
}

type tester struct {
	cmd         byte
	methods     []byte
	mthChosen   byte
	shallDenyHs bool
	neg         clSubneg
	rep1        byte // First reply code
	rep2        byte // Second reply code, used in BND only
	addrReq     *AddrPort
	addrRep1    *AddrPort
	addrRep2    *AddrPort
	tmntType    bool // True if we shall invoke terminator, false if close conn
	malf        malform
	rawHs       []byte
	rawReq      []byte

	conn    net.Conn
	capper  Capsulator
	test    *testing.T
	mux     sync.Mutex
	port    uint16
	hsChan  chan *Handshake
	reqChan chan any
	errChan chan *OpError
	mngr    *testMngr
	startT  time.Time
	stage   string
}

func newTester() *tester {
	t := new(tester)

	n := rand.Intn(3)
	switch n {
	case 0:
		t.cmd = CmdCONNECT
	case 1:
		t.cmd = CmdBIND
	case 2:
		t.cmd = CmdASSOC
	}

	n = rand.Intn(256)
	t.methods = make([]byte, n)
	_, err := crand.Read(t.methods)
	if err != nil {
		panic(err)
	}

	if rand.Intn(100) < 10 {
		t.mthChosen = MethodNoAccepted
	} else {
		t.mthChosen = byte(rand.Intn(256))
	}

	if t.mthChosen == MethodNoAccepted || !isByteOneOf(t.mthChosen, t.methods...) {
		t.shallDenyHs = true
	}

	switch rand.Intn(3) {
	case 0:
		t.neg = clNoAuthSubneg{}
	case 1:
		t.neg = newClUsrPwdSubneg()
	case 2:
		t.neg = new(capNeg)
	}

	if rand.Intn(100) < 75 {
		t.rep1 = RepSucceeded
	} else {
		t.rep1 = byte(rand.Intn(256))
	}
	if rand.Intn(100) < 50 {
		t.rep2 = RepSucceeded
	} else {
		t.rep2 = byte(rand.Intn(256))
	}

	t.addrReq = randAddr()
	t.addrRep1 = randAddr()
	t.addrRep2 = randAddr()

	t.tmntType = randBool()

	t.malf = newMalform()

	t.rawHs = make([]byte, 1+1+len(t.methods))
	t.rawHs[0] = VerSOCKS5
	t.rawHs[1] = byte(len(t.methods))
	copy(t.rawHs[2:], t.methods)

	aBytes, err := t.addrReq.MarshalBinary()
	if err != nil {
		panic(err)
	}
	l := 3 + len(aBytes)
	t.rawReq = make([]byte, l)
	t.rawReq[0] = VerSOCKS5
	t.rawReq[1] = t.cmd
	t.rawReq[2] = RSV
	copy(t.rawReq[3:], aBytes)

	t.applyMalform()

	return t
}

func (t *tester) applyMalform() {
	if t.malf.hsVer {
		t.rawHs[0] = byte(randIntExcept(256, int(VerSOCKS5)))
	}

	if t.malf.reqVer {
		t.rawReq[0] = byte(randIntExcept(256, int(VerSOCKS5)))
	}
	if t.malf.cmd {
		t.rawReq[1] = byte(randIntExcept(
			256,
			int(CmdCONNECT), int(CmdBIND), int(CmdASSOC),
		))
	}
	if t.malf.rsv {
		t.rawReq[2] = byte(randIntExcept(256, int(RSV)))
	}
	if t.malf.atyp {
		t.rawReq[3] = byte(randIntExcept(
			256,
			int(ATYPV4), int(ATYPV6), int(ATYPDOMAIN),
		))
	}
}

func (t *tester) String() string {
	s := fmt.Sprintf("tester %s\n", t.conn.LocalAddr())
	s += fmt.Sprintf("STAGE %s\n", t.getStage())
	s += fmt.Sprintf("METHODS % 02X\n", t.methods)
	s += fmt.Sprintf("CHOSEN %02X\n", t.mthChosen)
	s += fmt.Sprintf("IS ONE OF METHODS %t\n", isByteOneOf(t.mthChosen, t.methods...))
	s += fmt.Sprintf("SHALL DENY HS %t\n", t.shallDenyHs)
	s += fmt.Sprintf("NEG DETAIL:\n%s", t.neg.String())
	s += fmt.Sprintf("CMD %s REP1 %02X REP2 %02X\n", cmd2str(t.cmd), t.rep1, t.rep2)
	s += fmt.Sprintf("ADDR REQ %s\n", t.addrReq)
	s += fmt.Sprintf("ADDR REP1 %s\n", t.addrRep1)
	s += fmt.Sprintf("ADDR REP2 %s\n", t.addrRep2)
	s += fmt.Sprintf("TERMINATION TYPE %t\n", t.tmntType)
	s += fmt.Sprintf("MALF %s\n", (&t.malf).String())
	s += fmt.Sprintf("RAW HS % 02X\n", t.rawHs)
	s += fmt.Sprintf("RAW REQ % 02X\n", t.rawReq)
	s += fmt.Sprintf("TIME ELASPED %s\n", time.Now().Sub(t.startT))
	return s
}

func (t *tester) setStage(s string) {
	t.mux.Lock()
	defer t.mux.Unlock()
	t.stage = s
}

func (t *tester) getStage() string {
	t.mux.Lock()
	defer t.mux.Unlock()
	return t.stage
}

func (t *tester) start(mngr *testMngr) {
	t.startT = time.Now()
	t.setStage("dial")
	t.mngr = mngr
	t.test = mngr.t

	if !t.dialServer() {
		return
	}

	_, portS, err := net.SplitHostPort(t.conn.LocalAddr().String())
	if err != nil {
		panic(err)
	}
	var ok bool
	t.port, ok = parseUint16(portS)
	if !ok {
		panic("couldn't parse port from " + t.conn.LocalAddr().String())
	}

	t.test.Logf("tester %s starts", t.conn.LocalAddr())
	mngr.regTester(t)
	defer func() {
		t.test.Logf("tester %s quits", t.conn.LocalAddr())
		mngr.delTester(t)
	}()

	t.setStage("handshake")
	t.hsChan = make(chan *Handshake)

	time.Sleep(randLatency())

	if t.malf.shouldFailHandshake() {
		t.makeErrChan()

		if !t.writeHandshake() {
			return
		}

		t.chkMalformErr()

		t.closeErrChan()

		return
	}

	if !t.writeHandshake() {
		return
	}

	time.Sleep(randLatency())

	hs := t.rcvHs()
	close(t.hsChan)
	if hs == nil {
		return
	}

	if !t.chkHsMethods(hs) {
		return
	}

	if ok := t.chkAccpetHs(hs); !ok {
		return
	}

	if !t.chkHsReply() {
		return
	}

	if t.mthChosen == MethodNoAccepted {
		return
	}

	if t.shallDenyHs {
		return
	}

	t.setStage("subnegotiation")

  time.Sleep(randLatency())

	if ok := t.chkSubnegotiate(); !ok {
		return
	}

	if t.neg.isMalformed() {
		t.chkMalformErr()
		return
	}

	if t.neg.willFailAuth() {
		t.chkErrAuthFailed()
		return
	}

	t.setStage("request")

  time.Sleep(randLatency())

	if t.malf.shouldFailRequest() {
		t.makeErrChan()

		if !t.writeReq() {
			return
		}

		t.chkMalformErr()

		t.closeErrChan()

		return
	}

	if !t.writeReq() {
		return
	}

	t.reqChan = make(chan any)
	req := t.rcvReq()
	close(t.reqChan)
	if req == nil {
		return
	}

  time.Sleep(randLatency())

	switch req := req.(type) {
	case *ConnectRequest:
		t.testConnect(req)
	case *BindRequest:
		t.testBind(req)
	case *AssocRequest:
		t.testAssoc(req)
	default:
		t.test.Logf("received request of unknown type T from server, how??\nreq: %#v\n tester detail: \n%s\n", req, t.String())
		t.test.Fail()
	}

	return
}

func (t *tester) dialServer() (ok bool) {
	conn, err := net.Dial("tcp", t.mngr.s.Addr().String())
	if err != nil {
		t.test.Logf("tester failed to dial to server: %s", err)
		t.test.Fail()
		return false
	}
	t.conn = conn
	return true
}

func (t *tester) writeHandshake() (ok bool) {
	_, err := t.conn.Write(t.rawHs)
	if err != nil {
		if !t.malf.shouldFailHandshake() {
			t.test.Logf("tester failed to write handshake: %s", err)
			t.test.Fail()
			return false
		}
		t.test.Logf("error writing malformed handshake to server: %s", err)
	}
	return true
}

func (t *tester) chkMalformErr() {
	err := t.rcvErr()
	if !errors.Is(err, ErrMalformed) {
		t.test.Logf("should receive ErrMalformed from server, but got %s. tester detail: \n%s\n", err, t.String())
		t.test.Fail()
	}
}

func (t *tester) chkHsMethods(hs *Handshake) (ok bool) {
	if !reflect.DeepEqual(t.methods, hs.Methods()) {
		t.test.Logf("expected %02X as auth methods, but got %02X from server", t.methods, hs.Methods())
		t.test.Logf("tester detail: \n%s\n", t.String())
		t.test.Fail()
		return false
	}
	return true
}

func (t *tester) chkAccpetHs(hs *Handshake) (ok bool) {
	accepted := hs.Accept(t.mthChosen, t.neg.getServerSubneg())
	if t.shallDenyHs == accepted {
		msg := "server "
		if accepted {
			msg += "accepted "
		} else {
			msg += "denied "
		}
		msg += "handshake, but we expected it to "
		if t.shallDenyHs {
			msg += "deny it"
		} else {
			msg += "accept it"
		}
		t.test.Log(msg)
		t.test.Logf("tester detail: \n%s\n", t.String())
		t.test.Fail()
	}
	return
}

func (t *tester) chkHsReply() (ok bool) {
	hsReply := make([]byte, 2)
	_, err := io.ReadFull(t.conn, hsReply)
	if err != nil {
		t.test.Logf("tester failed to read handshake reply: %s", err)
		t.test.Fail()
		return false
	}

	if hsReply[0] != VerSOCKS5 {
		t.test.Logf("malformed reply from server?? reply: %02X tester detail: \n%s\n", hsReply, t.String())
		t.test.Fail()
		return false
	}

	if hsReply[1] != t.mthChosen && isByteOneOf(t.mthChosen, t.methods...) {
		t.test.Logf("server replied handshake with method %02X, but we want %02X", hsReply[1], t.mthChosen)
		t.test.Logf("tester detail: \n%s\n", t.String())
		t.test.Fail()
		return false
	}
	return true
}

func (t *tester) chkSubnegotiate() (ok bool) {
	var err error
	t.capper, err = t.neg.Negotiate(t.conn)
	if err != nil {
		t.test.Logf("failed to subnegotiate: %s. tester detail: \n%s\n", err, t.String())
		t.test.Fail()
		return false
	}
	return true
}

func (t *tester) chkErrAuthFailed() {
	opErr := t.rcvErr()
	if errors.Is(opErr, ErrAuthFailed) {
		return
	}
	t.test.Logf("expected ErrAuthFailed, but got %s", opErr)
	t.test.Logf("tester detail: %s", t.String())
	t.test.Fail()
	return
}

func (t *tester) writeReq() (ok bool) {
	if _, err := t.capper.Write(t.rawReq); err != nil {
		if !t.malf.shouldFailRequest() {
			t.test.Logf("tester failed to write request: %s", err)
			t.test.Fail()
			return false
		}
		t.test.Logf("error writing malformed request to server: %s", err)
	}
	return true
}

func (t *tester) rcvErr() *OpError {
	cancel := time.After(timeoutRcv)

	select {
	case <-cancel:
		t.test.Logf("timed out receiving error from test manager, tester detail: %s\n", t.String())
		t.test.Fail()
		return nil
	case err := <-t.errChan:
		return err
	}
}

func (t *tester) rcvHs() *Handshake {
	cancel := time.After(timeoutRcv)

	test := t.mngr.t

	select {
	case <-cancel:
		test.Logf("timed out receiving handshake from test manager, tester detail: %s\n", t.String())
		test.Fail()
		return nil
	case hs := <-t.hsChan:
		return hs
	}
}

func (t *tester) rcvReq() any {
	cancel := time.After(timeoutRcv)

	test := t.mngr.t

	select {
	case <-cancel:
		test.Logf("timed out receiving request from test manager, tester detail: %s\n", t.String())
		test.Fail()
		return nil
	case req := <-t.reqChan:
		return req
	}

}

func (t *tester) testConnect(req *ConnectRequest) {
	if t.rep1 == RepSucceeded {
		local, remote := newPipeConn(nil, t.addrRep1)

		if ok := req.Accept(local); !ok {
			t.test.Logf("failed to accept CONNECT request, tester detail: \n%s\n", t.String())
			t.test.Fail()
			return
		}

		if ok := t.chkReqReply(t.rep1, t.addrRep1); !ok {
			return
		}

		err := chkIntegrity(remote, t.capper)
		if err != nil {
			t.test.Logf("check CONNECT data integrity failed: %s. tester detail: \n%s\n", err, t.String())
			t.test.Fail()
		}
		return
	}

	req.Deny(t.rep1, t.addrRep1.String())

	t.chkReqReply(t.rep1, t.addrRep1)
	t.conn.Close()
}

func (t *tester) testBind(req *BindRequest) {
	if t.rep1 == RepSucceeded {
		req.Accept(t.addrRep1.String())
	} else {
		req.Deny(t.rep1, t.addrRep1.String())
	}

	if ok := t.chkReqReply(t.rep1, t.addrRep1); !ok || t.rep1 != RepSucceeded {
		return
	}

  time.Sleep(randLatency())

	var local, remote *pipeConn
	if t.rep2 == RepSucceeded {
		local, remote = newPipeConn(nil, t.addrRep2)

		if ok := req.Bind(local); !ok {
			t.test.Logf("couldn't bind. tester detail: \n%s\n", t.String())
			t.test.Fail()
			return
		}

		if ok := t.chkReqReply(t.rep2, t.addrRep2); !ok {
			return
		}

		if err := chkIntegrity(remote, t.capper); err != nil {
			t.test.Logf(
				"check integrity failed: %s. tester detail: \n%s\n",
				err, t.String(),
			)
			t.test.Fail()
		}
		return
	}

	if ok := req.DenyBind(t.rep2, t.addrRep2.String()); !ok {
		t.test.Logf("couldn't bind. tester detail: \n%s\n", t.String())
		t.test.Fail()
		return
	}

	t.chkReqReply(t.rep2, t.addrRep2)

	return
}

func (t *tester) testAssoc(req *AssocRequest) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	mux := sync.Mutex{}
	timedOut := false
	finished := false

	notify := func(reason error) {
		mux.Lock()
		defer mux.Unlock()
		if finished {
			return
		}
		finished = true
		timedOut = false

		wg.Done()
	}

	var terminate func() error
	if t.rep1 == RepSucceeded {
		terminate = req.Accept(t.addrRep1.String(), notify)
		if terminate == nil {
			t.test.Logf("failed to accept ASSOC. tester detail: \n%s\n", t.String())
			t.test.Fail()
			return
		}
	} else {
		if ok := req.Deny(t.rep1, t.addrRep1.String()); !ok {
			t.test.Logf("failed to deny ASSOC. tester detail: \n%s\n", t.String())
			t.test.Fail()
			return
		}
	}

	if ok := t.chkReqReply(t.rep1, t.addrRep1); !ok || t.rep1 != RepSucceeded {
		return
	}

	onTimeout := func() {
		mux.Lock()
		defer mux.Unlock()
		if finished {
			return
		}
		finished = true
		timedOut = true
		wg.Done()
	}

	if t.tmntType {
		if err := terminate(); err != nil {
			panic(err)
		}

		time.AfterFunc(50*time.Millisecond, onTimeout)

		wg.Wait()

		mux.Lock()
		defer mux.Unlock()
		if timedOut {
			t.test.Logf("server took too long to notify about the assoc termination. tester detail: \n%s\n", t.String())
			t.test.Fail()
		}
		return
	} else {
		if err := t.conn.Close(); err != nil {
			panic(err)
		}

		time.AfterFunc(50*time.Millisecond, onTimeout)

		wg.Wait()

		mux.Lock()
		defer mux.Unlock()
		if timedOut {
			t.test.Logf("server took too long to notify about the broken assoc. tester detail: \n%s\n", t.String())
			t.test.Fail()
		}
		return
	}
}

func (t *tester) chkReqReply(rep byte, addr *AddrPort) (ok bool) {
	reply, err := readReqReply(t.capper)
	if err != nil {
		t.test.Logf("failed to read reply from server: %s. tester detail: \n%s\n", err, t.String())
		t.test.Fail()
		return
	}
	if reply.rep != rep {
		t.test.Logf(
			"server replied with REP %02X, expected %02X. tester detail: \n%s\n",
			reply.rep, rep, t.String(),
		)
		t.test.Fail()
		return
	}
	if !reply.addr.Equal(addr) {
		t.test.Logf(
			"server replied with addr %s, expected %s. tester detail: \n%s\n",
			reply.addr, addr, t.String(),
		)
		t.test.Fail()
		return
	}
	return true
}

func (t *tester) makeErrChan() {
	t.mux.Lock()
	t.errChan = make(chan *OpError)
	t.mux.Unlock()
}

func (t *tester) closeErrChan() {
	t.mux.Lock()
	close(t.errChan)
	t.mux.Unlock()
}
