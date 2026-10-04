// Package llm implements the LLM provider client and the runtime config holder
// for rung 5. The provider client talks to an OpenAI-compatible /chat/completions
// endpoint; the holder carries the mutable LLM config that the /ctrl/llm
// endpoints read and update at runtime (no restart).
//
// Privacy: the query sent to a hosted endpoint leaves the deployment — runtime.md
// documents this as the honest exception. The provider is off unless enabled;
// a local OpenAI-compatible server keeps the guarantee end to end.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config is the mutable LLM runtime configuration. It mirrors config.LLM but
// lives in a thread-safe holder so the /ctrl/llm endpoints can update it without
// a restart. Empty fields mean "unset"; Enabled is derived from BaseURL.
type Config struct {
	BaseURL   string
	APIKey    string
	Model     string
	Timeout   int // seconds
	MaxTokens int
	Enabled   bool
}

// Holder is a thread-safe runtime config holder. Reads and writes are safe to
// call concurrently; the ladder reads the effective config per call.
type Holder struct {
	mu  sync.RWMutex
	cfg Config
}

// NewHolder returns a holder seeded with the boot config. Enabled is derived
// from BaseURL so a config with a URL is usable immediately.
func NewHolder(c Config) *Holder {
	if c.Enabled {
		c.Enabled = c.BaseURL != ""
	}
	h := &Holder{}
	h.mu.Lock()
	h.cfg = c
	h.mu.Unlock()
	return h
}

// Get returns the current config (safe copy).
func (h *Holder) Get() Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

// Set replaces the config. Enabled is recomputed from BaseURL.
func (h *Holder) Set(c Config) {
	if c.Enabled {
		// Enabled is derived: a config is only usable when a base URL exists.
		c.Enabled = c.BaseURL != ""
	}
	h.mu.Lock()
	h.cfg = c
	h.mu.Unlock()
}

// Enabled reports whether the LLM is usable right now.
func (h *Holder) Enabled() bool {
	return h.Get().Enabled
}

// Client is the provider client. It is stateless — the holder is read per call.
type Client struct {
	HTTP   *http.Client
	Holder *Holder
}

// NewClient returns a provider client reading config from the holder.
func NewClient(h *Holder) *Client {
	return &Client{Holder: h}
}

// ErrProvider is returned when the provider endpoint is unreachable or returned
// an error. It is distinct from ErrNotImplemented (no client) — here the client
// exists and ran, but the upstream failed.
var ErrProvider = errors.New("llm provider error")

// ErrDisabled is returned when the LLM is not enabled (no base URL).
var ErrDisabled = errors.New("llm not enabled")

// ErrNoResult is returned when the provider returned no usable candidates.
var ErrNoResult = errors.New("llm returned no candidates")

// chatRequest is the OpenAI-compatible chat completion request body.
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the OpenAI-compatible chat completion response body.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Complete sends the query to the provider and returns the raw text completion.
// The caller (ladder) parses the JSON the model was prompted to emit.
func (c *Client) Complete(ctx context.Context, query string) (string, error) {
	cfg := c.Holder.Get()
	if !cfg.Enabled || cfg.BaseURL == "" {
		return "", ErrDisabled
	}
	body := chatRequest{
		Model: cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: query},
		},
		MaxTokens:   cfg.MaxTokens,
		Temperature: 0,
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return "", err
	}
	// Timeout: 0 means "no deadline" — an unset timeout must not fire immediately.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Second)
	defer cancel()
	if cfg.Timeout <= 0 {
		cancel()
		ctx = context.Background()
	}

	url := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	resp, err := c.do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrProvider, err)
	}
	defer resp.Body.Close()
	var cr chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", fmt.Errorf("%w: decode: %v", ErrProvider, err)
	}
	if len(cr.Choices) == 0 || cr.Choices[0].Message.Content == "" {
		return "", ErrNoResult
	}
	return cr.Choices[0].Message.Content, nil
}

// do performs the request with the client's HTTP transport (defaulted to a
// sane timeout when the caller left it nil).
func (c *Client) do(req *http.Request) (*http.Response, error) {
	httpc := c.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return httpc.Do(req)
}

// systemPrompt is the instruction the provider receives before the user query.
// It asks the model to emit a JSON ResolveResponse so the ladder can map it.
const systemPrompt = `You are a geocoding assistant. Parse the user's query and respond with
JSON only, no prose. The JSON must match this shape:
{"candidates":[{"id":{"source":"gnaf|osm","pid":""},"kind":0,"point":{"lat":0,"lon":0},"source":"gnaf|osm","text":"","gnaf_pid":"","gnaf_confidence":0,"geocode_reliability":0,"match_score":0,"name":"","brand":"","operator":""}],"truncated":false,"total_matched":0,"generated_count":0,"dataset_version":"","ambiguous":[],"degraded":[]}
Fill only the fields you can infer. If you cannot resolve anything, return
{"candidates":[],"truncated":false,"total_matched":0,"generated_count":0,"dataset_version":"","ambiguous":[],"degraded":["llm-no-result"]}.`
