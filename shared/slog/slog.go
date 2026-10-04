// Package slog implements structured logging per INV-1: every log line is an
// event name plus key-value fields. Raw query text and request bodies NEVER
// appear (D-015/T9). This is the single logging seam — the server calls
// Log(level, event, fields...) and nothing else.
package slog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	default:
		return "error"
	}
}

// ParseLevel parses a level name.
func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	default:
		return LevelError
	}
}

// Logger writes one JSON line per event: {"level", "event", "time", ...fields}.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
	base  map[string]any // static fields (e.g. "service")
}

// New returns a Logger writing to out at the given level with optional base
// fields (e.g. {"service": "augeo"}).
func New(out io.Writer, level Level, base map[string]any) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{out: out, level: level, base: base}
}

// Log writes one line. The first argument is the event name; the rest are
// key-value pairs. An odd number of key-value args is a programming error and
// is logged as a warning (never silently dropped).
func (l *Logger) Log(level Level, event string, fields ...any) {
	if level < l.level {
		return
	}
	// Validate: event + even number of k/v args.
	if len(fields)%2 != 0 {
		l.writeRaw(LevelWarn, map[string]any{"event": "logger_mispaired_fields", "field": event})
		return
	}
	rec := map[string]any{
		"level": level.String(),
		"event": event,
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
	}
	for k, v := range l.base {
		rec[k] = v
	}
	for i := 0; i < len(fields); i += 2 {
		rec[fmt.Sprint(fields[i])] = fields[i+1]
	}
	l.writeRaw(level, rec)
}

// Info/Warn/Error/Debug are convenience wrappers: event first, then k/v pairs.
func (l *Logger) Info(event string, fields ...any)  { l.Log(LevelInfo, event, fields...) }
func (l *Logger) Warn(event string, fields ...any)  { l.Log(LevelWarn, event, fields...) }
func (l *Logger) Error(event string, fields ...any) { l.Log(LevelError, event, fields...) }
func (l *Logger) Debug(event string, fields ...any) { l.Log(LevelDebug, event, fields...) }

func (l *Logger) writeRaw(level Level, rec map[string]any) {
	rec["level"] = level.String()
	rec["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(l.out, `{"level":"error","event":"log_marshal_failed","error":%q}`+"\n", err.Error())
		return
	}
	fmt.Fprintln(l.out, string(b))
}
