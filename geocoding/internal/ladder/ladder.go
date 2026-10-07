// Package ladder implements the parse ladder — the front door of the geocoder.
// A single free-text query walks rungs 1–5, cheapest first, stopping at the
// first rung that clears its confidence threshold. Rungs 1–4 are deterministic
// and run unqueued behind a semaphore; rung 5 is the LLM and runs queued behind
// admission control, singleflight, deadline shedding and a circuit breaker.
package ladder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"augeocoding/internal/ranking"
	"ausystem/shared/contract"
	"ausystem/shared/normalise"
)

// Strategy names, exposed as `strategy` on every response.
const (
	StrategyCoord     = "coord"
	StrategyAddress   = "address"
	StrategyPOIAnchor = "poi_anchor"
	StrategyPOI       = "poi"
	StrategyLLM       = "llm"
)

// Rung is one step of the ladder. Each rung returns the strategy it fired and
// the response, or a sentinel "not applicable" error so the ladder falls through.
type Rung interface {
	Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error)
	// Kind names the endpoint this rung serves: "geocode" | "reverse" | "poi".
	// "search" (the front door) permits all rungs.
	Kind() string
}

// Query is the parsed intent for a single free-text request.
type Query struct {
	Raw    string
	Normal normalise.Result
	// Parsed fields, filled by whichever rung fires.
	Point   contract.Point
	Address string
	POIName string
	Anchor  *contract.Point
	Within  contract.LocalityID
}

// Result is the outcome of walking the ladder.
type Result struct {
	Strategy      string
	Response      contract.ResolveResponse
	Degraded      bool
	DegradeReason string
}

// Ladder walks the rungs in order.
type Ladder struct {
	Rungs []Rung
	// LLM rung, present only when configured.
	LLM *LLMRung
}

// ErrNoRung is returned when no rung applies to a query.
var ErrNoRung = errors.New("no parse rung applies")

// Walk runs rungs 1–4 in order. If none fires, and the LLM rung is configured,
// it delegates to the LLM (queued path). If the LLM is down (breaker open), it
// degrades to the best deterministic result.
func (l *Ladder) Walk(ctx context.Context, q Query) (Result, error) {
	return l.walk(ctx, q, "search")
}

// WalkKind is Walk constrained to one endpoint kind: "geocode" | "reverse" |
// "poi" | "parse". Only rungs whose Kind matches the requested kind participate,
// so a /geocode request never returns a POI strategy. "search" (default) means
// all rungs.
func (l *Ladder) WalkKind(ctx context.Context, q Query, kind string) (Result, error) {
	return l.walk(ctx, q, kind)
}

func (l *Ladder) walk(ctx context.Context, q Query, kind string) (Result, error) {
	for _, r := range l.Rungs {
		if kind != "search" && !rungServes(r, kind) {
			continue
		}
		strategy, resp, err := r.Try(ctx, q)
		if err == nil {
			return Result{Strategy: strategy, Response: resp}, nil
		}
		if !errors.Is(err, ErrNoRung) {
			return Result{}, err
		}
	}
	if l.LLM != nil {
		strategy, resp, err := l.LLM.Try(ctx, q)
		if err == nil {
			return Result{Strategy: strategy, Response: resp}, nil
		}
		if errors.Is(err, ErrLLMDegraded) {
			// LLM breaker open — fall back to the best deterministic rung.
			return l.bestDeterministic(ctx, q)
		}
		if errors.Is(err, ErrLLMNotImplemented) {
			// The LLM rung is configured but not wired. This is a server-side
			// gap, not a client error — propagate it so the handler can report
			// 501 (not 400 "no rung applies").
			return Result{}, err
		}
		if err != nil {
			return Result{}, err
		}
	}
	return Result{}, ErrNoRung
}

// bestDeterministic reruns the deterministic rungs and returns the best result,
// marked degraded. This is the circuit-breaker fallback (runtime.md).
func (l *Ladder) bestDeterministic(ctx context.Context, q Query) (Result, error) {
	var best Result
	var bestScore float64
	for _, r := range l.Rungs {
		strategy, resp, err := r.Try(ctx, q)
		if err != nil {
			continue
		}
		s := scoreResponse(resp)
		if s > bestScore {
			bestScore = s
			best = Result{Strategy: strategy, Response: resp, Degraded: true, DegradeReason: "llm-unavailable"}
		}
	}
	if best.Strategy == "" {
		return Result{}, ErrNoRung
	}
	return best, nil
}

func scoreResponse(r contract.ResolveResponse) float64 {
	if len(r.Candidates) == 0 {
		return 0
	}
	return float64(ranking.Composite(r.Candidates[0]))
}

var coordRe = regexp.MustCompile(`-?\d+(\.\d+)?\s*[, ]\s*-?\d+(\.\d+)`)

// coordRung is rung 1: a bare coordinate string.
type coordRung struct{}

func (coordRung) Kind() string { return "coord" }

func (coordRung) Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error) {
	m := coordRe.FindString(q.Raw)
	if m == "" {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	parts := strings.FieldsFunc(m, func(r rune) bool { return r == ',' || r == ' ' })
	if len(parts) != 2 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	lat, err1 := strconv.ParseFloat(parts[0], 64)
	lon, err2 := strconv.ParseFloat(parts[1], 64)
	if err1 != nil || err2 != nil {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	// Bounds-check to the AU bbox (T4: coordinates from untrusted input).
	if lat < -60 || lat > -9 || lon < 110 || lon > 160 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	p := contract.Point{Lat: lat, Lon: lon}
	return StrategyCoord, contract.ResolveResponse{Candidates: []contract.Candidate{{
		Kind: contract.KindAddress, Point: p, Source: "coord",
		Text: fmt.Sprintf("%.5f, %.5f", lat, lon),
	}}}, nil
}

// addressRung is rung 2: a street address.
type addressRung struct {
	res contract.Resolver
}

func (addressRung) Kind() string { return "address" }

func (r addressRung) Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error) {
	if !q.Normal.HadStreet || !q.Normal.HadNumbers {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	req := contract.ResolveRequest{
		Kind:     contract.KindAddress,
		Generate: q.Normal.Generate,
		Score:    q.Normal.Tokens,
		State:    q.Normal.State,
		Postcode: q.Normal.Postcode,
		Limit:    20,
	}
	resp, err := r.res.Resolve(ctx, req)
	if err != nil {
		// ErrOutOfScope must propagate, never become an empty result (T4/D-032).
		if errors.Is(err, contract.ErrOutOfScope) {
			return "", resp, err
		}
		// ErrNoCandidates means this rung matched nothing — fold into ErrNoRung
		// so walk() continues to the next rung / returns "no rung applies"
		// (400), not "no candidates" (404). Same garbage must return the same
		// status on every endpoint (UX review finding #5).
		if errors.Is(err, contract.ErrNoCandidates) {
			return "", contract.ResolveResponse{}, ErrNoRung
		}
		return "", resp, err
	}
	if len(resp.Candidates) == 0 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	return StrategyAddress, resp, nil
}

// poiAnchorRung is rung 3: POI name + anchor (near/at/in/corner of).
type poiAnchorRung struct {
	res contract.Resolver
}

func (poiAnchorRung) Kind() string { return "poi" }

var connectorRe = regexp.MustCompile(`\b(near|at|in|on|corner of|cnr|&|,)\b`)

func (r poiAnchorRung) Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error) {
	if !q.Normal.IsPOI {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	// Partition the string on a connector keyword.
	idx := connectorRe.FindStringIndex(q.Raw)
	if idx == nil {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	left := strings.TrimSpace(q.Raw[:idx[0]])
	right := strings.TrimSpace(q.Raw[idx[1]:])
	if left == "" || right == "" {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	// Anchor: resolve the right fragment as an address (rung 2 logic).
	anchorReq := contract.ResolveRequest{
		Kind:     contract.KindAddress,
		Generate: normalise.Normalise(right).Generate,
		Score:    normalise.Normalise(right).Tokens,
		Limit:    20,
	}
	anchorResp, err := r.res.Resolve(ctx, anchorReq)
	if err != nil {
		// Fold ErrNoCandidates into ErrNoRung (see addressRung).
		if errors.Is(err, contract.ErrNoCandidates) {
			return "", contract.ResolveResponse{}, ErrNoRung
		}
		return "", contract.ResolveResponse{}, err
	}
	if len(anchorResp.Candidates) == 0 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	anchor := anchorResp.Candidates[0].Point
	// POI: resolve the left fragment as a named place near the anchor.
	poiReq := contract.ResolveRequest{
		Kind:     contract.KindPOI,
		Generate: normalise.Normalise(left).Generate,
		Score:    normalise.Normalise(left).Tokens,
		Anchor:   &anchor,
		Limit:    20,
	}
	poiResp, err := r.res.Resolve(ctx, poiReq)
	if err != nil {
		// Fold ErrNoCandidates into ErrNoRung (see addressRung).
		if errors.Is(err, contract.ErrNoCandidates) {
			return "", contract.ResolveResponse{}, ErrNoRung
		}
		return "", contract.ResolveResponse{}, err
	}
	if len(poiResp.Candidates) == 0 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	return StrategyPOIAnchor, poiResp, nil
}

// poiRung is rung 4: a bare POI name (no anchor, no address).
type poiRung struct {
	res contract.Resolver
}

func (poiRung) Kind() string { return "poi" }

func (r poiRung) Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error) {
	if !q.Normal.IsPOI || len(q.Normal.Tokens) == 0 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	req := contract.ResolveRequest{
		Kind:     contract.KindPOI,
		Generate: q.Normal.Generate,
		Score:    q.Normal.Tokens,
		Limit:    20,
	}
	resp, err := r.res.Resolve(ctx, req)
	if err != nil {
		// Fold ErrNoCandidates into ErrNoRung (see addressRung).
		if errors.Is(err, contract.ErrNoCandidates) {
			return "", contract.ResolveResponse{}, ErrNoRung
		}
		return "", resp, err
	}
	if len(resp.Candidates) == 0 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	return StrategyPOI, resp, nil
}

// ErrLLMDegraded means the LLM rung was skipped by the circuit breaker.
var ErrLLMDegraded = errors.New("llm degraded")

// NewCoordRung returns rung 1 (bare coordinate).
func NewCoordRung() Rung { return coordRung{} }

// NewAddressRung returns rung 2 (street address).
func NewAddressRung(res contract.Resolver) Rung { return addressRung{res: res} }

// NewPOIAnchorRung returns rung 3 (POI name + anchor).
func NewPOIAnchorRung(res contract.Resolver) Rung { return poiAnchorRung{res: res} }

// NewPOIRung returns rung 4 (bare POI name).
func NewPOIRung(res contract.Resolver) Rung { return poiRung{res: res} }

// NewBreaker returns a circuit breaker with the given threshold and cooldown.
func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	return &Breaker{Threshold: threshold, Cooldown: cooldown}
}

// rungServes reports whether a rung participates in a kind-constrained walk.
// Rungs carry a distinct Kind (coord/address/poi); the endpoint kind maps to
// the set of rungs that can satisfy it.
func rungServes(r Rung, kind string) bool {
	k := r.Kind()
	switch kind {
	case "geocode":
		return k == "coord" || k == "address"
	case "reverse":
		// /reverse is served by the reverse rung (real RTree nearest) OR the
		// coord rung (a bare coordinate echo). Both accept a coordinate; the
		// reverse rung returns actual nearest addresses, the coord rung echoes.
		return k == "reverse" || k == "coord"
	case "poi":
		return k == "poi"
	case "parse":
		return false // parse is LLM-only; deterministic rungs never serve it
	default:
		return true // search / unknown: all rungs
	}
}

// reverseRung is rung 2r: a coordinate → nearest addresses (real RTree reverse
// geocoding). It sends KindReverse with MaxRadiusM to the resolver and returns
// actual nearest addresses, not a coordinate echo. This is the fix for the
// /reverse stub (the coord rung returned the input point as a "candidate").
type reverseRung struct {
	res contract.Resolver
}

func (reverseRung) Kind() string { return "reverse" }

func (r reverseRung) Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error) {
	// /reverse sends a JSON body {"lat":...,"lon":...} (handleReverse), not a
	// bare coordinate string. Parse both forms: a JSON lat/lon object (the
	// /reverse endpoint) or a "lat, lon" text (the coord rung).
	lat, lon, ok := reverseCoord(q.Raw)
	if !ok {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	if lat < -60 || lat > -9 || lon < 110 || lon > 160 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	anchor := contract.Point{Lat: lat, Lon: lon}
	req := contract.ResolveRequest{
		Kind:       contract.KindReverse,
		Anchor:     &anchor,
		Limit:      5,
		MaxRadiusM: 10000, // widen up to 10km if the tight bbox is empty
	}
	resp, err := r.res.Resolve(ctx, req)
	if err != nil {
		// Fold ErrNoCandidates into ErrNoRung (see addressRung).
		if errors.Is(err, contract.ErrNoCandidates) {
			return "", contract.ResolveResponse{}, ErrNoRung
		}
		return "", resp, err
	}
	if len(resp.Candidates) == 0 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	return StrategyCoord, resp, nil
}

// reverseCoord extracts lat/lon from a /reverse request. The endpoint sends
// JSON {"lat":..,"lon":..}; the coord rung sends "lat, lon" text. Both are
// accepted; anything else is not a reverse candidate.
func reverseCoord(raw string) (lat, lon float64, ok bool) {
	raw = strings.TrimSpace(raw)
	// Try JSON first.
	var obj struct {
		Lat float64 `json:"lat"`
		Lon float64 `json:"lon"`
	}
	if err := json.Unmarshal([]byte(raw), &obj); err == nil && obj.Lat != 0 && obj.Lon != 0 {
		return obj.Lat, obj.Lon, true
	}
	// Try "lat, lon" text.
	m := coordRe.FindString(raw)
	if m == "" {
		return 0, 0, false
	}
	parts := strings.FieldsFunc(m, func(r rune) bool { return r == ',' || r == ' ' })
	if len(parts) != 2 {
		return 0, 0, false
	}
	lat, err1 := strconv.ParseFloat(parts[0], 64)
	lon, err2 := strconv.ParseFloat(parts[1], 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return lat, lon, true
}

// NewReverseRung returns rung 2r (coordinate → nearest addresses).
func NewReverseRung(res contract.Resolver) Rung { return reverseRung{res: res} }

// LLMRung is rung 5. It is present only when configured (runtime.md: "the LLM
// only sees genuinely messy input"). It carries the two-class concurrency:
// admission, singleflight, deadline shedding, per-key in-flight cap, breaker.
type LLMRung struct {
	// Configured is set by the caller; if false, the rung is absent.
	Configured bool
	// Admit is the bounded queue admission control. Returns false when full.
	Admit func() bool
	// Release is called exactly once after Admit admitted a request, on both
	// success and error paths, to return the queue slot (adversarial review M2).
	Release func()
	// Singleflight collapses identical in-flight queries.
	Singleflight *sync.Map
	// Breaker is the circuit breaker state.
	Breaker *Breaker
	// Provider is the LLM provider client (OpenAI-compatible). When nil the
	// rung reports ErrLLMNotImplemented — configured but not wired.
	Provider interface {
		Complete(ctx context.Context, query string) (string, error)
	}
}

// Breaker is a simple circuit breaker.
type Breaker struct {
	mu     sync.Mutex
	failed int
	open   bool
	opened time.Time
	// Threshold opens after this many consecutive failures.
	Threshold int
	// Cooldown is how long the breaker stays open.
	Cooldown time.Duration
}

func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		if time.Since(b.opened) >= b.Cooldown {
			b.open = false
			b.failed = 0
			return true // half-open probe
		}
		return false
	}
	return true
}

func (b *Breaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failed = 0
	b.open = false
}

func (b *Breaker) Failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failed++
	if b.failed >= b.Threshold {
		b.open = true
		b.opened = time.Now()
	}
}

func (r *LLMRung) Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error) {
	if !r.Configured {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	if !r.Breaker.Allow() {
		return "", contract.ResolveResponse{}, ErrLLMDegraded
	}
	// Per-caller admission (Queue.PerKeyInflight) comes before the shared
	// queue, so one caller cannot hold every queue slot.
	g := gateFrom(ctx)
	if g.Enter != nil {
		leave, err := g.Enter()
		if err != nil {
			return "", contract.ResolveResponse{}, err
		}
		if leave != nil {
			defer leave()
		}
	}
	if !r.Admit() {
		return "", contract.ResolveResponse{}, ErrQueueFull
	}
	// Release the queue slot exactly once, on every path after Admit admitted.
	if r.Release != nil {
		defer r.Release()
	}
	// Singleflight: collapse identical in-flight queries.
	key := hashQuery(q.Raw)
	if v, ok := r.Singleflight.Load(key); ok {
		return StrategyLLM, v.(contract.ResolveResponse), nil
	}
	// Deadline shedding: if the request already timed out, drop it.
	if ctx.Err() != nil {
		return "", contract.ResolveResponse{}, ctx.Err()
	}
	if r.Provider == nil {
		return "", contract.ResolveResponse{}, ErrLLMNotImplemented
	}
	// Count the call against the caller's LLM budget before spending it.
	if g.Charge != nil {
		if err := g.Charge(); err != nil {
			return "", contract.ResolveResponse{}, err
		}
	}
	resp, err := r.callLLM(ctx, q)
	if err != nil {
		r.Breaker.Failure()
		return "", contract.ResolveResponse{}, err
	}
	r.Breaker.Success()
	r.Singleflight.Store(key, resp)
	// Evict the dedupe entry after serving so the map cannot grow unbounded
	// with distinct query hashes (adversarial review M1). Concurrent requests
	// for the same key still collapse: they Load before this Store and read the
	// in-flight entry; only subsequent requests re-compute.
	r.Singleflight.Delete(key)
	return StrategyLLM, resp, nil
}

// callLLM is the seam — the real LLM call. When Provider is nil the rung
// reports ErrLLMNotImplemented (configured but not wired); callers map that to
// 501. With a provider the query is sent to the OpenAI-compatible endpoint and
// the model's JSON output is parsed into a ResolveResponse.
func (r *LLMRung) callLLM(ctx context.Context, q Query) (contract.ResolveResponse, error) {
	if r.Provider == nil {
		return contract.ResolveResponse{}, ErrLLMNotImplemented
	}
	raw, err := r.Provider.Complete(ctx, q.Raw)
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	var resp contract.ResolveResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return contract.ResolveResponse{}, fmt.Errorf("%w: model output not JSON: %v", ErrLLMNotImplemented, err)
	}
	// The model output is untrusted (adversarial review C2): a prompt-injection
	// into the model can yield arbitrary text/name/brand and out-of-bounds
	// coordinates. Sanitize every candidate before it reaches the caller:
	// clamp coordinates to the AU bbox, drop candidates the model invents
	// outside scope, and strip markup from free-text fields so a downstream
	// consumer rendering them as HTML is not XSS-vulnerable.
	sanitizeLLMCandidates(&resp)
	return resp, nil
}

// sanitizeLLMCandidates strips untrusted model output down to safe values.
// The model is not a trusted data source — a prompt-injection can make it
// emit arbitrary free text, invented identifiers, or out-of-scope coordinates.
// We clamp to the AU bbox, drop out-of-scope candidates, and remove markup
// from free-text fields (text/name/brand/operator) so downstream consumers
// that render them as HTML are not XSS-vulnerable.
func sanitizeLLMCandidates(resp *contract.ResolveResponse) {
	out := resp.Candidates[:0]
	for _, c := range resp.Candidates {
		// Clamp coordinates to the AU bbox (mirrors the coord rung's T4 check).
		if c.Point.Lat < -60 || c.Point.Lat > -9 || c.Point.Lon < 110 || c.Point.Lon > 160 {
			continue // drop out-of-scope candidate
		}
		c.Text = stripMarkup(c.Text)
		c.Name = stripMarkup(c.Name)
		c.Brand = stripMarkup(c.Brand)
		c.Operator = stripMarkup(c.Operator)
		out = append(out, c)
	}
	resp.Candidates = out
}

// stripMarkup removes HTML/script markup from a free-text field. It is not a
// full HTML sanitizer — it neutralizes the breakout characters that make a
// string dangerous when rendered as HTML (adversarial review C2).
func stripMarkup(s string) string {
	if !strings.ContainsAny(s, "<>") {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<', '>':
			// Drop angle brackets entirely; keep the rest of the text.
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// ErrLLMNotImplemented is returned when the LLM rung is configured but the LLM
// provider client is not wired. It is distinct from ErrNoRung (no rung applies
// to this input) and from ErrLLMDegraded (breaker open) — it means the rung
// exists but cannot run.
var ErrLLMNotImplemented = errors.New("llm not implemented")

// ErrQueueFull is returned when the LLM queue is at capacity.
var ErrQueueFull = errors.New("llm queue full")

func hashQuery(raw string) string {
	// SHA-256 of the raw query, in-memory only (D-015: never persisted/logged).
	// The hash is a dedupe key, not a retention mechanism.
	var h uint64 = 14695981039346656037
	for _, c := range raw {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return strconv.FormatUint(h, 16)
}
