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
	// Limit caps the candidates a rung asks for (Limits.MaxResults, or less
	// when the caller's remaining quota is smaller). 0 means the rung default.
	Limit int
}

// limit returns q.Limit, or def when the caller set none. def also caps it:
// each rung has a ceiling of its own that a larger Limit must not lift.
func (q Query) limit(def int) int {
	if q.Limit > 0 && q.Limit < def {
		return q.Limit
	}
	return def
}

// defaultLimit is the candidate cap a forward rung asks places for when the
// caller set none; it matches places' own maxResults clamp.
const defaultLimit = 20

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
	// /reverse is coordinates in, addresses out: there is nothing for a model
	// to interpret, and a coordinate the reverse rung could not place must not
	// become a paid LLM call.
	if l.LLM != nil && kind != "reverse" {
		strategy, resp, err := l.LLM.Try(ctx, q)
		if err == nil {
			return Result{Strategy: strategy, Response: resp}, nil
		}
		if errors.Is(err, ErrLLMDegraded) {
			// LLM breaker open — fall back to the best deterministic rung.
			return l.bestDeterministic(ctx, q, kind)
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
// marked degraded. This is the circuit-breaker fallback (runtime.md). It is
// bound by the endpoint kind like the walk itself: /geocode must not come back
// with a POI because the LLM happened to be down. With nothing to offer, the
// caller hears the LLM is unavailable (ErrLLMDegraded), not that its input was
// unparseable.
func (l *Ladder) bestDeterministic(ctx context.Context, q Query, kind string) (Result, error) {
	var best Result
	var bestScore float64
	for _, r := range l.Rungs {
		if kind != "search" && !rungServes(r, kind) {
			continue
		}
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
		return Result{}, ErrLLMDegraded
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
	// Places decides how specific an answer the text supports: an address, the
	// centre of a street, locality or postcode (Candidate.Precision), or none,
	// in which case the walk moves on to the POI rungs. A street with no number
	// or a bare locality is not a POI query just because it has no number.
	if len(q.Normal.Tokens) == 0 {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	req := contract.ResolveRequest{
		Kind:     contract.KindAddress,
		Generate: q.Normal.Generate,
		Score:    q.Normal.Tokens,
		State:    q.Normal.State,
		Postcode: q.Normal.Postcode,
		Limit:    q.limit(defaultLimit),
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
		Limit:    defaultLimit,
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
		Limit:    q.limit(defaultLimit),
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
		Limit:    q.limit(defaultLimit),
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
		// /reverse is served by the reverse rung alone. The coord rung would
		// also accept "lat, lon" text, and since it runs first it would echo
		// the input point back instead of the nearest addresses.
		return k == "reverse"
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
		Limit:      q.limit(5),
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
