package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHolderSetEnabledDerived(t *testing.T) {
	h := NewHolder(Config{BaseURL: "", Enabled: true})
	if h.Enabled() {
		t.Fatal("Enabled should be derived from BaseURL; empty BaseURL => disabled")
	}
	h.Set(Config{BaseURL: "http://llm:8080", Enabled: true})
	if !h.Enabled() {
		t.Fatal("BaseURL set => enabled")
	}
}

func TestHolderGetSafeCopy(t *testing.T) {
	h := NewHolder(Config{BaseURL: "http://a", Model: "m1", MaxTokens: 256})
	got := h.Get()
	if got.BaseURL != "http://a" || got.Model != "m1" || got.MaxTokens != 256 {
		t.Fatalf("unexpected copy: %+v", got)
	}
}

func TestClientComplete(t *testing.T) {
	// Mock OpenAI-compatible endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("missing bearer: %q", r.Header.Get("Authorization"))
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req["model"] != "m1" {
			t.Fatalf("model: %v", req["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"candidates\":[]}"}}]}`))
	}))
	defer srv.Close()

	h := NewHolder(Config{BaseURL: srv.URL, APIKey: "test-key", Model: "m1", Enabled: true, Timeout: 5})
	c := NewClient(h)
	got, err := c.Complete(context.Background(), "123 main st")
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"candidates":[]}` {
		t.Fatalf("unexpected completion: %q", got)
	}
}

func TestClientDisabled(t *testing.T) {
	h := NewHolder(Config{BaseURL: ""})
	c := NewClient(h)
	_, err := c.Complete(context.Background(), "q")
	if err != ErrDisabled {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
}

// The provider call runs under the request context even when Timeout is 0
// (the old behaviour replaced it with context.Background()).
func TestClientHonoursRequestDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := NewClient(NewHolder(Config{BaseURL: srv.URL, Enabled: true, Timeout: 0}))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Complete(ctx, "q")
	if err == nil || !errors.Is(err, ErrProvider) {
		t.Fatalf("want provider error on deadline, got %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("call ignored the request deadline (%v)", d)
	}
}

func TestClientRejectsNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"candidates\":[]}"}}]}`))
	}))
	defer srv.Close()
	c := NewClient(NewHolder(Config{BaseURL: srv.URL, Enabled: true, Timeout: 5}))
	if _, err := c.Complete(context.Background(), "q"); !errors.Is(err, ErrProvider) || !strings.Contains(err.Error(), "429") {
		t.Fatalf("429 from provider: %v", err)
	}
}

func TestClientBoundsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A valid JSON prefix that never ends inside the cap.
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"`))
		_, _ = w.Write(bytes.Repeat([]byte("a"), 2*maxResponseBytes))
		_, _ = w.Write([]byte(`"}}]}`))
	}))
	defer srv.Close()
	c := NewClient(NewHolder(Config{BaseURL: srv.URL, Enabled: true, Timeout: 5}))
	if _, err := c.Complete(context.Background(), "q"); !errors.Is(err, ErrProvider) {
		t.Fatalf("oversized body: %v", err)
	}
}
