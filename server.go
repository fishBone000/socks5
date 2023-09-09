// Package s5i provides a SOCKS5 server that lets external code accept/deny requests and attach outbound connections.
package s5i

import (
	"fmt"
	"net"
	"sync"
)

const (
	LogChanCap = 64
)

type Server struct {
	addr     *net.TCPAddr
	listener *net.TCPListener

	mux       sync.Mutex
	logChan   chan LogEntry
	started   bool
	down      bool
	closables map[closable]struct{}
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
	s.info(nil, TypeListener, "listener started at", s.listener.Addr())

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
	err := s.listener.Close()
	delete(s.closables, s.listener)
	s.onErr(err, TypeListener, "failed to close listener")
}

// CloseAll closes the internal listener and all connections.
// If anything except the internal listener has failed to close,
// Close() won't be called on it during the future calls of CloseAll().
func (s *Server) CloseAll() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.down = true
	s.onErr(s.listener.Close(), TypeListener, "failed to close listener")
	delete(s.closables, s.listener)
	for c := range s.closables {
		switch c.(type) {
		case net.Conn:
			s.onErr(c.Close(), TypeConn, "failed to close connection")
		default:
			s.onErr(c.Close(), TypeUnknown, "failed to close")
			s.debug(nil, TypeUnknown, fmt.Sprintf("unknown closable %#v", c))
		}
		delete(s.closables, c)
	}
}

func (s *Server) regClosable(c closable) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.closables[c] = struct{}{}
}

func (s *Server) delClosable(c closable) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.closables, c)
}

// Get LogEntry channel from the Server.
// If it's the first time that this function is called on the Server, LogChan()
// creates a channel for the server, and then the server can use this channel
// to send LogEntrys. Any LogEntrys created before the channel creation are
// discarded.
// Any LogEntry channel returned by LogChan() is buffered with size of LogChanCap.
// If the channel returned is full, any LogEntry trying to send through it is
// disgarded.
func (s *Server) LogChan() <-chan LogEntry {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.logChan == nil {
		s.logChan = make(chan LogEntry, LogChanCap)
	}
	return (<-chan LogEntry)(s.logChan)
}

func (s *Server) listen() {
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			s.mux.Lock()
			defer s.mux.Unlock()
			if !s.down {
				s.err(err, TypeListener, "error listening for handshakes")
				s.down = true
			}
			return
		}

		s.regClosable(conn)

    go s.handleNewClient(conn)
	}
}

func (s *Server) handleNewClient(conn *net.TCPConn) {
}
