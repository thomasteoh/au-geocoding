package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
