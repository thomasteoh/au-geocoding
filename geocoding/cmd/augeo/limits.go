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
	"augeocoding/internal/llm"
	"augeocoding/internal/placesclient"
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

// rowReservation is the row quota a request holds while it works (D-034:
// quota is per result row). Rows are reserved before any resolver or LLM
// work and the request is then limited to what it holds, so no work is done
// that will not be paid for: charging afterwards let a caller near its
// ceiling have the work done and then be refused, repeatably and for free.
// settle returns the unused part once the real row count is known.
type rowReservation struct {
	p       publicapi.Principal
	ip      string
	store   *publicapi.Store
	perIP   int64
	granted int64
}

// reserveRows takes up to want rows from the caller's daily quota: keyed rows
// from the usage table, anonymous rows from the in-memory per-IP counter
// (D-026). A zero grant means the caller is at its ceiling. A store fault is
// an error, never a quota refusal: a broken app.db must read as a 5xx, not
// as "you are over quota".
func reserveRows(p publicapi.Principal, ip string, want int64, store *publicapi.Store, cfg config.Config) (rowReservation, error) {
	r := rowReservation{p: p, ip: ip, store: store, perIP: cfg.Rate.AnonDaily}
	if p.Anonymous() {
		r.granted = store.ReserveAnonRows(ip, want, cfg.Rate.AnonDaily, cfg.Rate.AnonDailyGlobal)
		return r, nil
	}
	g, err := store.ReserveRows(p, want)
	if err != nil {
		return rowReservation{}, err
	}
	r.granted = g
	return r, nil
}

// limit is the candidate cap the request may ask for: what it holds.
func (r rowReservation) limit() int { return int(r.granted) }

// settle refunds the rows reserved but not used. used never exceeds the
// grant: callers trim results to limit() first.
func (r rowReservation) settle(used int64) error {
	unused := r.granted - used
	if unused <= 0 {
		return nil
	}
	if r.p.Anonymous() {
		r.store.RefundAnonRows(r.ip, unused, r.perIP)
		return nil
	}
	return r.store.RefundRows(r.p, unused)
}

// settleLogged settles and logs a failed refund (the caller is then
// over-charged by the unused rows, never under-charged).
func (r rowReservation) settleLogged(used int64, log *slog.Logger, endpoint string) {
	if err := r.settle(used); err != nil && log != nil {
		log.Warn("quota_refund_failed", "endpoint", endpoint, "err_type", fmt.Sprintf("%T", err))
	}
}

// trimToLimit caps a result to the rows the request holds.
func trimToLimit(res *ladder.Result, n int) {
	if len(res.Response.Candidates) > n {
		res.Response.Candidates = res.Response.Candidates[:n]
		res.Response.Truncated = true
	}
}

// batchLLMGate makes a batch's rung-5 admission wait for a slot instead of
// failing. A batch runs Batch.Workers items at once, more than the caller's
// Queue.PerKeyInflight, and its own items must not knock each other out with
// llm_busy. Items queue behind at most PerKeyInflight of the batch's own LLM
// calls; the shared per-key cap still applies on top, so a batch and the same
// caller's single requests together stay within it.
func batchLLMGate(ctx context.Context, g ladder.LLMGate, perKey int) ladder.LLMGate {
	if perKey < 1 {
		perKey = 1
	}
	slots := make(chan struct{}, perKey)
	enter := g.Enter
	g.Enter = func() (func(), error) {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var leave func()
		if enter != nil {
			var err error
			if leave, err = enter(); err != nil {
				<-slots
				return nil, err
			}
		}
		return func() {
			if leave != nil {
				leave()
			}
			<-slots
		}, nil
	}
	return g
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
		// The LLM rung is configured but not wired — a server-side gap, not
		// a client error.
		return http.StatusNotImplemented, "llm not implemented", "llm_not_implemented"
	case errors.Is(err, ladder.ErrLLMBadOutput), errors.Is(err, llm.ErrNoResult):
		// The provider answered, but not with anything usable: an upstream
		// fault, not a missing feature.
		return http.StatusBadGateway, "llm returned an unusable answer", "llm_bad_output"
	case errors.Is(err, llm.ErrProvider):
		return http.StatusBadGateway, "llm provider error", "llm_provider"
	case errors.Is(err, ladder.ErrLLMDegraded):
		return http.StatusServiceUnavailable, "llm unavailable", "llm_degraded"
	case errors.Is(err, llm.ErrDisabled):
		// Switched off at runtime while the request was in flight.
		return http.StatusServiceUnavailable, "llm not enabled", "llm_disabled"
	case errors.Is(err, placesclient.ErrContractMismatch):
		return http.StatusBadGateway, "upstream contract mismatch", "contract_mismatch"
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
