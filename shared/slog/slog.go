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
// key-value pairs. Field handling, in order:
//
//   - Keys must be strings. A non-string key is replaced by "!BADKEY" so a
//     value passed in key position never becomes a JSON key.
//   - Reserved keys (level, event, time, logger_error and every base field such
//     as service) cannot be overwritten; a caller field using one is written
//     under "field_<key>" instead.
//   - Keys on the secret denylist (see isSecretKey) have their value replaced
//     by "REDACTED".
//   - error values are written as their Error() string (encoding/json would
//     otherwise serialise most errors as {}).
//   - An odd number of field args is a programming error: the line is still
//     written, the unpaired trailing arg is dropped (it may be query text, so
//     it is never emitted) and logger_error is set to "odd_field_count".
func (l *Logger) Log(level Level, event string, fields ...any) {
	if level < l.level {
		return
	}
	rec := make(map[string]any, len(l.base)+len(fields)/2+3)
	for k, v := range l.base {
		rec[k] = v
	}
	rec["event"] = event
	n := len(fields)
	if n%2 != 0 {
		rec["logger_error"] = "odd_field_count"
		n--
	}
	for i := 0; i < n; i += 2 {
		k, ok := fields[i].(string)
		if !ok {
			k = "!BADKEY"
		}
		if l.reserved(k) {
			k = "field_" + k
		}
		v := fields[i+1]
		if isSecretKey(k) {
			v = redacted
		} else {
			v = loggable(v)
		}
		rec[k] = v
	}
	l.writeRaw(level, rec)
}

const redacted = "REDACTED"

// reserved reports whether k is written by the logger itself and therefore
// may not be set by a caller field.
func (l *Logger) reserved(k string) bool {
	switch k {
	case "level", "event", "time", "logger_error":
		return true
	}
	_, ok := l.base[k]
	return ok
}

// secretKeys are normalised (lower case, separators removed) field names
// whose values are never logged.
var secretKeys = map[string]bool{
	"key": true, "apikey": true, "xapikey": true,
	"token": true, "accesstoken": true, "refreshtoken": true, "idtoken": true, "bearer": true,
	"secret": true, "clientsecret": true, "secretkey": true,
	"password": true, "passwd": true, "pass": true, "pwd": true,
	"authorization": true, "proxyauthorization": true,
	"cookie": true, "setcookie": true, "session": true, "sessionid": true,
	"assertion": true, "samlresponse": true, "samlrequest": true,
	// Bare "code" is deliberately absent: it is the usual key for error and
	// status codes (mail_failed code=dial_550). OAuth codes use these names.
	"authcode": true, "authorizationcode": true, "oauthcode": true, "otp": true, "privatekey": true, "credential": true, "credentials": true,
}

// isSecretKey reports whether a field key names a secret. Matching is on the
// normalised key: an exact denylist entry, or a name ending in token, secret,
// password or apikey (e.g. ctrl_token, client-secret, smtp_password).
func isSecretKey(k string) bool {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	nk := b.String()
	if secretKeys[nk] {
		return true
	}
	for _, suf := range []string{"token", "secret", "password", "apikey"} {
		if strings.HasSuffix(nk, suf) {
			return true
		}
	}
	return false
}

// loggable converts values encoding/json renders badly: errors become their
// message, and values that cannot be marshalled at all (funcs, channels) are
// replaced by a type marker so the rest of the line is still written.
func loggable(v any) (out any) {
	switch t := v.(type) {
	case nil, string, bool, int, int64, int32, uint, uint64, float64, float32:
		return v
	case error:
		defer func() {
			if recover() != nil { // typed-nil error whose Error() panics
				out = fmt.Sprintf("!ERROR(%T)", t)
			}
		}()
		return t.Error()
	}
	if _, err := json.Marshal(v); err != nil {
		return fmt.Sprintf("!UNMARSHALABLE(%T)", v)
	}
	return v
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
