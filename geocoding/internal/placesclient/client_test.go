package placesclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"ausystem/shared/contract"
)

// fakePlaces mimics au-places' version gate: a request naming a version other
// than want is refused with "contract version mismatch" before anything else.
func fakePlaces(t *testing.T, want string, conns *atomic.Int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	gate := func(w http.ResponseWriter, r *http.Request) bool {
		if v := r.Header.Get(contract.ContractVersionHeader); v != "" && v != want {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "contract version mismatch"})
			return false
		}
		return true
	}
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ready","dataset_version":"d1"}`))
	})
	mux.HandleFunc("/suggest", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"empty prefix"}`))
	})
	mux.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		// A long error body: the client must drain it to reuse the connection.
		_, _ = w.Write([]byte(`{"error":"no candidates"}` + string(make([]byte, 2048))))
	})
	srv := httptest.NewUnstartedServer(mux)
	if conns != nil {
		srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				conns.Add(1)
			}
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestContractMismatchIsDistinct(t *testing.T) {
	srv := fakePlaces(t, "v2", nil)
	c := New(srv.URL)
	_, err := c.Resolve(context.Background(), contract.ResolveRequest{})
	if !errors.Is(err, ErrContractMismatch) || errors.Is(err, contract.ErrNoCandidates) {
		t.Fatalf("resolve against v2 places: %v", err)
	}
	if _, err := c.Suggest(context.Background(), contract.SuggestRequest{Prefix: "x"}); !errors.Is(err, ErrContractMismatch) {
		t.Fatalf("suggest against v2 places: %v", err)
	}
	if err := c.CheckContract(context.Background()); !errors.Is(err, ErrContractMismatch) {
		t.Fatalf("CheckContract: %v", err)
	}
	if ready, _, err := c.Ready(context.Background()); ready || !errors.Is(err, ErrContractMismatch) {
		t.Fatalf("Ready on a mismatched upstream: %v %v", ready, err)
	}
}

func TestContractMatchAndNoCandidates(t *testing.T) {
	srv := fakePlaces(t, contract.Version, nil)
	c := New(srv.URL)
	if err := c.CheckContract(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ready, ds, err := c.Ready(context.Background()); !ready || ds != "d1" || err != nil {
		t.Fatalf("Ready: %v %q %v", ready, ds, err)
	}
	if _, err := c.Resolve(context.Background(), contract.ResolveRequest{}); !errors.Is(err, contract.ErrNoCandidates) {
		t.Fatalf("plain 400: %v", err)
	}
}

// A response that echoes a different version is refused even on 200.
func TestResponseVersionHeaderChecked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(contract.ContractVersionHeader, "v9")
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL).Resolve(context.Background(), contract.ResolveRequest{}); !errors.Is(err, ErrContractMismatch) {
		t.Fatalf("v9 echo: %v", err)
	}
}

// Error responses are drained, so repeated failures reuse one connection.
func TestErrorBodiesDrainedForReuse(t *testing.T) {
	var conns atomic.Int64
	srv := fakePlaces(t, contract.Version, &conns)
	c := New(srv.URL)
	for i := 0; i < 10; i++ {
		_, _ = c.Resolve(context.Background(), contract.ResolveRequest{})
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d connections for 10 sequential requests", n)
	}
}
