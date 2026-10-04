package secretbox

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	b, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := b.Seal("client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if s == "client-secret" {
		t.Fatal("sealed value equals plaintext")
	}
	got, err := b.Open(s)
	if err != nil || got != "client-secret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if e, _ := b.Seal(""); e != "" {
		t.Fatal("empty should seal to empty")
	}
}

func TestOpenRejectsTamperAndWrongKey(t *testing.T) {
	b, _ := New(bytes.Repeat([]byte{1}, 32))
	other, _ := New(bytes.Repeat([]byte{2}, 32))
	s, _ := b.Seal("x")
	if _, err := other.Open(s); err != ErrOpen {
		t.Fatalf("wrong key: %v", err)
	}
	tampered := s[:len(s)-2] + "AA"
	if _, err := b.Open(tampered); err != ErrOpen {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := b.Open("plain"); err != ErrOpen {
		t.Fatalf("no prefix: %v", err)
	}
}

func TestParseKey(t *testing.T) {
	k := bytes.Repeat([]byte{9}, 32)
	for _, s := range []string{hex.EncodeToString(k), base64.StdEncoding.EncodeToString(k), base64.RawURLEncoding.EncodeToString(k)} {
		got, err := ParseKey(s)
		if err != nil || !bytes.Equal(got, k) {
			t.Fatalf("ParseKey(%q) = %v, %v", s, got, err)
		}
	}
	if _, err := ParseKey("short"); err == nil {
		t.Fatal("short key accepted")
	}
}
