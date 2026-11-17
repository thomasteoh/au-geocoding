// Package placesclient implements the contract.Resolver in split mode: it calls
// the au-places HTTP API. In single-binary mode the same interface is satisfied
// by an in-process call, so neither deployment pays for the other.
package placesclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"ausystem/shared/contract"
)

// ErrContractMismatch means au-places speaks a different contract version.
// Every request would fail the same way, so it must surface as a deployment
// fault (boot failure, not-ready), never as "no candidates".
var ErrContractMismatch = errors.New("places contract version mismatch")

// contractMismatchMsg is the wire error au-places sends for a version it does
// not implement (places/internal/api).
const contractMismatchMsg = "contract version mismatch"

// maxErrorBody bounds how much of an error response is read or drained.
const maxErrorBody = 4096

// closeBody drains a bounded remainder and closes the body, so the keep-alive
// connection goes back to the pool instead of being torn down.
func closeBody(b io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(b, maxErrorBody))
	_ = b.Close()
}

// errorString reads the {"error": "..."} body au-places sends with a 4xx.
func errorString(b io.Reader) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(b, maxErrorBody)).Decode(&e)
	return e.Error
}

// checkVersion reports a response that names a contract version other than
// ours. A response without the header predates the echo and is accepted.
func (c *Client) checkVersion(resp *http.Response) error {
	if v := resp.Header.Get(contract.ContractVersionHeader); v != "" && v != c.ExpectedContractVersion {
		return fmt.Errorf("%w: places speaks %q, augeo expects %q", ErrContractMismatch, v, c.ExpectedContractVersion)
	}
	return nil
}

// Client is a split-mode resolver backed by the au-places HTTP API.
type Client struct {
	baseURL string
	http    *http.Client
	// ExpectedContractVersion is sent with each request; a mismatch is a startup
	// failure, not a per-request error (contract.md § Versioning).
	ExpectedContractVersion string

	contractOK atomic.Bool
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
	defer closeBody(resp.Body)
	if err := c.checkVersion(resp); err != nil {
		return false, "", err
	}
	// Any 2xx means the upstream is ready (it may not expose a rich body).
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// A healthy upstream on the wrong contract is not ready for us:
		// every request would be refused.
		if err := c.CheckContract(ctx); err != nil {
			return false, "", err
		}
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

// CheckContract asks au-places whether it implements our contract version.
// au-places checks the version header before anything else on /suggest, so a
// request with an empty prefix gets "contract version mismatch" when the
// versions differ and "empty prefix" when they agree, without touching the
// database. It returns ErrContractMismatch on a mismatch, nil when the
// versions agree or the upstream cannot tell us (no /suggest), and any other
// error when the probe could not run. A matched result is remembered.
func (c *Client) CheckContract(ctx context.Context) error {
	if c.contractOK.Load() {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/suggest", bytes.NewReader([]byte(`{"prefix":""}`)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(contract.ContractVersionHeader, c.ExpectedContractVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contract check: %w", err)
	}
	defer closeBody(resp.Body)
	if err := c.checkVersion(resp); err != nil {
		return err
	}
	if resp.StatusCode == http.StatusBadRequest && errorString(resp.Body) == contractMismatchMsg {
		return fmt.Errorf("%w: places refused contract %q", ErrContractMismatch, c.ExpectedContractVersion)
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("contract check: upstream status %d", resp.StatusCode)
	}
	c.contractOK.Store(true)
	return nil
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
	defer closeBody(resp.Body)
	if err := c.checkVersion(resp); err != nil {
		return contract.SuggestResponse{}, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest && errorString(resp.Body) == contractMismatchMsg {
			return contract.SuggestResponse{}, ErrContractMismatch
		}
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
	defer closeBody(resp.Body)
	if err := c.checkVersion(resp); err != nil {
		return contract.ResolveResponse{}, err
	}

	// Typed errors (contract.md § Error taxonomy): a 503 or 404 maps to the
	// contract error the caller needs. Never an empty result for a state the
	// build excludes (ErrOutOfScope).
	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to decode
	case http.StatusServiceUnavailable:
		return contract.ResolveResponse{}, contract.ErrNotLoaded
	case http.StatusBadRequest:
		switch errorString(resp.Body) {
		case "out_of_scope":
			return contract.ResolveResponse{}, contract.ErrOutOfScope
		case contractMismatchMsg:
			// Not "no results": the request never reached the matcher.
			return contract.ResolveResponse{}, ErrContractMismatch
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
