package socksy5

import (
	"fmt"
	"time"
)

// Severity levels used by [LogEntry].
const (
	SeverityDebug   = "debug"
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// A LogEntry contains time stamp, severity and corresponding error message.
//
// The returned string of its Error func doesn't include timestamp and severity.
type LogEntry struct {
	Time      time.Time // Timestamp
	Severity  string    // Severity of this error, one of severity constants
	Verbosity int       // Used by debug entries, higher means more verbose, starts from 0
	Err       error     // Inner error
}

func (e *LogEntry) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Err.Error()
}

func (e *LogEntry) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// String returns a string representation of LogEntry, in the format of
// [SEVERITY] HH:MM:SS ERROR
//
// If e.Severity is SeverityDebug, SEVERITY is followed by a space and e.Verbosity.
func (e *LogEntry) String() string {
	if e == nil {
		return "<nil>"
	}
	s := "["
	s += e.Severity
	if e.Severity == SeverityDebug {
		s += fmt.Sprintf(" %d", e.Verbosity)
	}
	s += "] "
	s += e.Time.Format(time.TimeOnly)
	s += " " + e.Err.Error()
	return s
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

func (s *Server) dbg(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityDebug,
		Err:      err(e, a...),
	}
	s.sendLog(log)
}

func (s *Server) dbgv(e error, a ...any) {
	log := LogEntry{
		Time:      time.Now(),
		Severity:  SeverityDebug,
		Verbosity: 1,
		Err:       err(e, a...),
	}
	s.sendLog(log)
}

func (s *Server) dbgvv(e error, a ...any) {
	log := LogEntry{
		Time:      time.Now(),
		Severity:  SeverityDebug,
		Verbosity: 2,
		Err:       err(e, a...),
	}
	s.sendLog(log)
}

func (s *Server) dbgNonNil(e error, a ...any) {
	if e != nil {
		s.dbg(e, a...)
	}
}

func (s *Server) info(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityInfo,
		Err:      err(e, a...),
	}
	s.sendLog(log)
}

func (s *Server) infoNonNil(e error, a ...any) {
	if e != nil {
		s.info(e, a...)
	}
}

func (s *Server) warn(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityWarning,
		Err:      err(e, a...),
	}
	s.sendLog(log)
}

func (s *Server) warnNonNil(e error, a ...any) {
	if e != nil {
		s.warn(e, a...)
	}
}

func (s *Server) err(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityError,
		Err:      err(e, a...),
	}
	s.sendLog(log)
}

func (s *Server) errNonNil(e error, a ...any) {
	if e != nil {
		s.err(e, a...)
	}
}
