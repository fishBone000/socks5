package s5i

import (
	"time"
)

// Severity levels used by LogEntry
const (
	SeverityDebug   = "debug"
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// If TypeUnknown is actually used in runtime, it means there's bug

const (
	TypeListener = "listener"
	TypeClose    = "close"
	TypeConn     = "conn"
	TypeAuth     = "auth"
	TypeUnknown  = "unknown"
	TypeGeneral  = "general"
)

// SOCKS5 Server Interface outputs LogEntrys which have time stamp, severity, type and corresponding error message.
// The returned string of its Error() func doesn't include timestamp and severity.
// If timestamp or/and severity is required, do formatting yourself before write it to logs.
type LogEntry struct {
	Time     time.Time // Timestamp
	Severity string    // Severity of this error, one of severity constants
	Type     string    // Type of this error, one of type constants
	Err      error     // Error message
}

func (e LogEntry) Error() string {
	return e.Err.Error()
}

func (e LogEntry) Unwrap() error {
	return e.Err
}

func (e LogEntry) withSeverity(severity string) LogEntry {
	e.Severity = severity
	return e
}

func (s *Server) sendLog(l LogEntry) {
	if s.logChan == nil {
		return
	}
	select {
	case s.logChan <- l:
	default:
	}
}

func (s *Server) debug(e error, t string, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityDebug,
		Err:      err(e, a...),
		Type:     t,
	}
	s.sendLog(log)
}

func (s *Server) dbgNonNil(e error, t string, a ...any) {
	if e != nil {
		s.debug(e, t, a...)
	}
}

func (s *Server) info(e error, t string, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityInfo,
		Err:      err(e, a...),
		Type:     t,
	}
	s.sendLog(log)
}

func (s *Server) infoNonNil(e error, t string, a ...any) {
	if e != nil {
		s.info(e, t, a...)
	}
}

func (s *Server) warn(e error, t string, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityWarning,
		Err:      err(e, a...),
		Type:     t,
	}
	s.sendLog(log)
}

func (s *Server) warnNonNil(e error, t string, a ...any) {
	if e != nil {
		s.warn(e, t, a...)
	}
}

func (s *Server) err(e error, t string, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityError,
		Err:      err(e, a...),
		Type:     t,
	}
	s.sendLog(log)
}

func (s *Server) errNonNil(e error, t string, a ...any) {
	if e != nil {
		s.err(e, t, a...)
	}
}
