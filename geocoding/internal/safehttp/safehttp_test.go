package safehttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "::1": false, "fe80::1": false,
		"fc00::1": false, "::ffff:127.0.0.1": false, "0.0.0.0": false, "64:ff9b::a00:1": false,
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := Client(5*time.Second, false).Get(srv.URL)
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback fetch: %v", err)
	}
	resp, err := Client(5*time.Second, true).Get(srv.URL)
	if err != nil {
		t.Fatalf("allowPrivate fetch: %v", err)
	}
	resp.Body.Close()
}
