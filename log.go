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
	Verbosity int       // Used by debug entries, the higher the more verbose, starts from 0
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

func (ml *MidLayer) sendLog(l LogEntry) {
	ml.logChanMux.Lock()
	defer ml.logChanMux.Unlock()
	select {
	case ml.logChan <- l:
	default:
	}
}

func (ml *MidLayer) dbg(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityDebug,
		Err:      err(e, a...),
	}
	ml.sendLog(log)
}

func (ml *MidLayer) dbgv(e error, a ...any) {
	log := LogEntry{
		Time:      time.Now(),
		Severity:  SeverityDebug,
		Verbosity: 1,
		Err:       err(e, a...),
	}
	ml.sendLog(log)
}

func (ml *MidLayer) dbgvv(e error, a ...any) {
	log := LogEntry{
		Time:      time.Now(),
		Severity:  SeverityDebug,
		Verbosity: 2,
		Err:       err(e, a...),
	}
	ml.sendLog(log)
}

func (ml *MidLayer) dbgNonNil(e error, a ...any) {
	if e != nil {
		ml.dbg(e, a...)
	}
}

func (ml *MidLayer) info(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityInfo,
		Err:      err(e, a...),
	}
	ml.sendLog(log)
}

func (ml *MidLayer) infoNonNil(e error, a ...any) {
	if e != nil {
		ml.info(e, a...)
	}
}

func (ml *MidLayer) warn(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityWarning,
		Err:      err(e, a...),
	}
	ml.sendLog(log)
}

func (ml *MidLayer) warnNonNil(e error, a ...any) {
	if e != nil {
		ml.warn(e, a...)
	}
}

func (ml *MidLayer) err(e error, a ...any) {
	log := LogEntry{
		Time:     time.Now(),
		Severity: SeverityError,
		Err:      err(e, a...),
	}
	ml.sendLog(log)
}

func (ml *MidLayer) errNonNil(e error, a ...any) {
	if e != nil {
		ml.err(e, a...)
	}
}
