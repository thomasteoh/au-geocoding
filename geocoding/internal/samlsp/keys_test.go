package samlsp

import (
	"crypto/tls"
	"testing"
)

func TestNewKeyPair(t *testing.T) {
	k, c, err := NewKeyPair("augeo-sp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair([]byte(c), []byte(k)); err != nil {
		t.Fatalf("key and cert do not match: %v", err)
	}
}
