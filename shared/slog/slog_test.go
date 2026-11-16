package slog

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func logOne(t *testing.T, fn func(l *Logger)) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	l := New(&buf, LevelDebug, map[string]any{"service": "svc"})
	fn(l)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("want exactly one line, got %q", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("line is not JSON: %v: %s", err, lines[0])
	}
	return rec
}

func TestReservedKeysNotOverwritten(t *testing.T) {
	rec := logOne(t, func(l *Logger) {
		l.Info("real_event", "event", "spoofed", "service", "evil", "level", "debug", "time", "x")
	})
	if rec["event"] != "real_event" || rec["service"] != "svc" || rec["level"] != "info" || rec["time"] == "x" {
		t.Fatalf("reserved key overwritten: %v", rec)
	}
	if rec["field_event"] != "spoofed" || rec["field_service"] != "evil" {
		t.Fatalf("caller values not preserved under field_ prefix: %v", rec)
	}
}

func TestErrorsSerialiseAsMessage(t *testing.T) {
	rec := logOne(t, func(l *Logger) {
		l.Error("failed", "error", errors.New("disk full"), "wrapped", errors.Join(errors.New("a"), errors.New("b")))
	})
	if rec["error"] != "disk full" || rec["wrapped"] != "a\nb" {
		t.Fatalf("errors not rendered as strings: %v", rec)
	}
}

type nilErr struct{ msg *string }

func (e *nilErr) Error() string { return *e.msg }

func TestTypedNilErrorDoesNotPanic(t *testing.T) {
	var e *nilErr
	rec := logOne(t, func(l *Logger) { l.Error("failed", "error", error(e)) })
	if s, _ := rec["error"].(string); !strings.HasPrefix(s, "!ERROR(") {
		t.Fatalf("typed nil error = %v", rec["error"])
	}
}

func TestOddFieldCountKeepsLine(t *testing.T) {
	rec := logOne(t, func(l *Logger) { l.Info("evt", "a", 1, "12 high st doncaster") })
	if rec["event"] != "evt" || rec["a"] != float64(1) || rec["logger_error"] != "odd_field_count" {
		t.Fatalf("odd count handling: %v", rec)
	}
	// INV-1: the unpaired trailing arg may be query text; it must not appear
	// as a key or value.
	for k, v := range rec {
		if strings.Contains(k, "high st") || v == "12 high st doncaster" {
			t.Fatalf("unpaired arg leaked: %v", rec)
		}
	}
}

func TestSecretKeysRedacted(t *testing.T) {
	rec := logOne(t, func(l *Logger) {
		l.Info("evt",
			"api_key", "sk-123", "key", "k", "X-Api-Key", "k2", "token", "t", "ctrl_token", "c",
			"client-secret", "s", "Password", "p", "authorization", "Bearer x", "cookie", "c=1",
			"assertion", "PHNhbWw+", "auth_code", "authcode", "SAMLResponse", "r", "code", "dial_550",
			"key_id", "kid-1", "endpoint", "/search", "max_tokens", 100)
	})
	for _, k := range []string{"api_key", "key", "X-Api-Key", "token", "ctrl_token", "client-secret", "Password", "authorization", "cookie", "assertion", "auth_code", "SAMLResponse"} {
		if rec[k] != "REDACTED" {
			t.Errorf("%s = %v, want REDACTED", k, rec[k])
		}
	}
	if rec["key_id"] != "kid-1" || rec["code"] != "dial_550" || rec["endpoint"] != "/search" || rec["max_tokens"] != float64(100) {
		t.Fatalf("non-secret keys altered: %v", rec)
	}
}

func TestBadKeyAndUnmarshalable(t *testing.T) {
	rec := logOne(t, func(l *Logger) { l.Info("evt", 42, "v", "fn", func() {}) })
	if rec["!BADKEY"] != "v" {
		t.Fatalf("non-string key: %v", rec)
	}
	if s, _ := rec["fn"].(string); !strings.HasPrefix(s, "!UNMARSHALABLE(") {
		t.Fatalf("unmarshalable value: %v", rec)
	}
}

func TestLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelWarn, nil)
	l.Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("info logged at warn level: %s", buf.String())
	}
}
