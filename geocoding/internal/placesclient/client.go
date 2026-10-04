// Package placesclient implements the contract.Resolver in split mode: it calls
// the au-places HTTP API. In single-binary mode the same interface is satisfied
// by an in-process call, so neither deployment pays for the other.
package placesclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"ausystem/shared/contract"
)

// Client is a split-mode resolver backed by the au-places HTTP API.
type Client struct {
	baseURL string
	http    *http.Client
	// ExpectedContractVersion is sent with each request; a mismatch is a startup
	// failure, not a per-request error (contract.md § Versioning).
	ExpectedContractVersion string
}

// New returns a Client for the au-places base URL.
func New(baseURL string) *Client {
	return &Client{
		baseURL:                 baseURL,
		http:                    &http.Client{Timeout: 30 * time.Second},
		ExpectedContractVersion: contract.Version,
	}
}

// Ready probes the upstream resolver's readiness (split mode). Returns the
// upstream's ready status, dataset version if reported, and any error. In
// single-binary mode this is a no-op (the resolver is in-process).
//
// The probe timeout is generous (30s) because au-places' readyz runs a cold
// dataset-count query that can take >5s on first hit (observed 11s on the
// 4.18M-row vic.db); a 5s probe reports "not_ready" against a healthy upstream.
func (c *Client) Ready(ctx context.Context) (ready bool, dataset string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/readyz", nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set(contract.ContractVersionHeader, c.ExpectedContractVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	// Any 2xx means the upstream is ready (it may not expose a rich body).
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Best-effort: read the dataset version if present. au-places emits
		// "dataset_version" (not "dataset") in its readyz body.
		var b struct {
			DatasetVersion string `json:"dataset_version"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&b)
		return true, b.DatasetVersion, nil
	}
	return false, "", fmt.Errorf("upstream readyz status %d", resp.StatusCode)
}
func (c *Client) Suggest(ctx context.Context, req contract.SuggestRequest) (contract.SuggestResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return contract.SuggestResponse{}, fmt.Errorf("marshal suggest request: %w", err)
	}
	url := c.baseURL + "/suggest"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return contract.SuggestResponse{}, fmt.Errorf("new suggest request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(contract.ContractVersionHeader, c.ExpectedContractVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return contract.SuggestResponse{}, fmt.Errorf("suggest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return contract.SuggestResponse{}, fmt.Errorf("upstream suggest status %d", resp.StatusCode)
	}
	var out contract.SuggestResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return contract.SuggestResponse{}, fmt.Errorf("decode suggest response: %w", err)
	}
	return out, nil
}

func (c *Client) Resolve(ctx context.Context, req contract.ResolveRequest) (contract.ResolveResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return contract.ResolveResponse{}, fmt.Errorf("marshal request: %w", err)
	}
	url := c.baseURL + "/resolve"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return contract.ResolveResponse{}, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(contract.ContractVersionHeader, c.ExpectedContractVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return contract.ResolveResponse{}, fmt.Errorf("resolve: %w", err)
	}
	defer resp.Body.Close()

	// Typed errors (contract.md § Error taxonomy): a 503 or 404 maps to the
	// contract error the caller needs. Never an empty result for a state the
	// build excludes (ErrOutOfScope).
	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decode
	case http.StatusServiceUnavailable:
		return contract.ResolveResponse{}, contract.ErrNotLoaded
	case http.StatusBadRequest:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		if e.Error == "out_of_scope" {
			return contract.ResolveResponse{}, contract.ErrOutOfScope
		}
		return contract.ResolveResponse{}, contract.ErrNoCandidates
	default:
		return contract.ResolveResponse{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var out contract.ResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return contract.ResolveResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}
