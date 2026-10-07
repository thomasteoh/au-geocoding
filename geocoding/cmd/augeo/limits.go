package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"augeocoding/internal/config"
	"augeocoding/internal/ladder"
	"augeocoding/internal/publicapi"
	"ausystem/shared/contract"
	"ausystem/shared/slog"
)

// apiLimits is the per-process admission state the handlers share:
// in-flight LLM requests per caller (Queue.PerKeyInflight) and running
// batches per caller (Batch.MaxConcurrentPerKey).
type apiLimits struct {
	llm   inflight
	batch inflight
}

// inflight counts concurrent operations per key.
type inflight struct {
	mu sync.Mutex
	n  map[string]int
}

// acquire takes a slot for key when fewer than max are held (max < 1 is
// treated as 1: a zero would otherwise disable the cap).
func (f *inflight) acquire(key string, max int) bool {
	if max < 1 {
		max = 1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == nil {
		f.n = make(map[string]int)
	}
	if f.n[key] >= max {
		return false
	}
	f.n[key]++
	return true
}

func (f *inflight) release(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n[key] <= 1 {
		delete(f.n, key)
		return
	}
	f.n[key]--
}

// llmGate builds the rung-5 spend control for one request: a per-caller
// in-flight slot, then one counted LLM call against the caller's daily cap
// (anonymous: AnonLLM per IP and global; keyed: the tier's LLM quota).
func (lim *apiLimits) llmGate(p publicapi.Principal, ip string, store *publicapi.Store, cfg config.Config) ladder.LLMGate {
	key := p.RateKey
	return ladder.LLMGate{
		Enter: func() (func(), error) {
			if !lim.llm.acquire(key, cfg.Queue.PerKeyInflight) {
				return nil, ladder.ErrLLMBusy
			}
			return func() { lim.llm.release(key) }, nil
		},
		Charge: func() error {
			if p.Anonymous() {
				if !store.ChargeAnonLLM(ip, cfg.AnonLLM.DailyPerIP, cfg.AnonLLM.DailyGlobal) {
					return ladder.ErrLLMQuota
				}
				return nil
			}
			if err := store.ChargeLLMCall(p); err != nil {
				if errors.Is(err, publicapi.ErrLLMQuotaExceeded) {
					return ladder.ErrLLMQuota
				}
				return err
			}
			return nil
		},
	}
}

// preflight refuses a request whose caller has no row quota left today,
// before any ladder work or LLM spend.
func preflight(p publicapi.Principal, ip string, store *publicapi.Store, cfg config.Config) (bool, error) {
	if p.Anonymous() {
		return !store.AnonAtCeiling(ip, cfg.Rate.AnonDaily, cfg.Rate.AnonDailyGlobal), nil
	}
	left, err := store.QuotaRemaining(p)
	if err != nil {
		return false, err
	}
	return left > 0, nil
}

// chargeRows charges result rows after a successful request: keyed rows to
// the usage table, anonymous rows to the in-memory per-IP counter (D-026).
func chargeRows(p publicapi.Principal, ip string, rows int64, store *publicapi.Store, cfg config.Config) bool {
	if !p.Anonymous() {
		ok, _ := store.ChargePrincipal(p, rows)
		return ok
	}
	ok, _ := store.ChargeAnonDaily(ip, rows, cfg.Rate.AnonDaily, cfg.Rate.AnonDailyGlobal)
	return ok
}

// billableRows is what a result costs: its row count, but at least one row
// when the LLM rung served it (a 0-candidate LLM answer still spent a call).
func billableRows(res ladder.Result) int64 {
	rows := int64(len(res.Response.Candidates))
	if res.Strategy == ladder.StrategyLLM && rows < 1 {
		rows = 1
	}
	return rows
}

// errorResponse maps a request error to the status and the fixed message a
// caller sees. Internal errors never reach the caller as text: reason is a
// short code for the log, and the log carries the error's type, never its
// message (which can hold query text or upstream detail).
func errorResponse(err error) (status int, msg, reason string) {
	switch {
	case errors.Is(err, contract.ErrOutOfScope):
		return http.StatusBadRequest, "out of scope", "out_of_scope"
	case errors.Is(err, contract.ErrNoCandidates):
		return http.StatusNotFound, "no candidates", "no_candidates"
	case errors.Is(err, ladder.ErrNoRung):
		// No rung applies to this input for the requested endpoint kind — a
		// client error, not a server failure (e.g. an address string sent to
		// /reverse).
		return http.StatusBadRequest, "no parse rung applies", "no_rung"
	case errors.Is(err, ladder.ErrQueueFull):
		return http.StatusTooManyRequests, "queue full", "queue_full"
	case errors.Is(err, ladder.ErrLLMBusy):
		return http.StatusTooManyRequests, "too many llm requests in flight", "llm_busy"
	case errors.Is(err, ladder.ErrLLMQuota):
		return http.StatusTooManyRequests, "llm quota exceeded", "llm_quota"
	case errors.Is(err, ladder.ErrLLMNotImplemented):
		// The LLM rung is configured but not wired (or its output was
		// unusable) — a server-side gap, not a client error.
		return http.StatusNotImplemented, "llm not implemented", "llm_not_implemented"
	case errors.Is(err, contract.ErrNotLoaded):
		return http.StatusServiceUnavailable, "not loaded", "not_loaded"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "timeout", "deadline"
	case errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable, "request cancelled", "canceled"
	default:
		return http.StatusInternalServerError, "internal error", "internal"
	}
}

// logRequestError logs the reason code and error type for server-side
// failures. Client errors (4xx) are not logged.
func logRequestError(log *slog.Logger, endpoint string, status int, reason string, err error) {
	if status < 500 || log == nil {
		return
	}
	log.Warn("request_error", "endpoint", endpoint, "status", status, "reason", reason, "err_type", fmt.Sprintf("%T", err))
}

// clientAddr returns the exact client address. X-Forwarded-For is consulted
// only when the direct peer is a trusted proxy; it is then walked from the
// right (the entry the nearest proxy appended), skipping trusted proxies,
// and the first untrusted address is the client. The leftmost entry is
// whatever the client sent and is never trusted on its own. A malformed
// entry falls back to the peer, so garbage cannot mint fresh rate-limit
// keys. The zero Addr means the peer address itself was unparseable.
func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseHostAddr(r.RemoteAddr)
	if !peer.IsValid() || !isTrusted(peer, trusted) {
		return peer
	}
	var entries []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		entries = append(entries, strings.Split(h, ",")...)
	}
	addr := peer
	for i := len(entries) - 1; i >= 0; i-- {
		a := parseHostAddr(strings.TrimSpace(entries[i]))
		if !a.IsValid() {
			return peer
		}
		addr = a
		if !isTrusted(a, trusted) {
			return a
		}
	}
	// Every hop was a trusted proxy: the leftmost one is the client.
	return addr
}

// clientIP returns the rate-limit and quota key for the client: an IPv4
// address as is, an IPv6 address as its /64 prefix (one subscriber usually
// holds a whole /64, so per-address keys would be free to multiply).
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	a := clientAddr(r, trusted)
	if !a.IsValid() {
		return r.RemoteAddr
	}
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}

// parseHostAddr parses "ip", "ip:port" or "[ip]:port", unmapping
// IPv4-in-IPv6 and dropping any zone.
func parseHostAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.Addr{}
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
