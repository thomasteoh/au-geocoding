package ladder

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"ausystem/shared/contract"
)

// LLMRung is rung 5. It is present only when configured (runtime.md: "the LLM
// only sees genuinely messy input"). It carries the two-class concurrency:
// admission, singleflight, deadline shedding, per-key in-flight cap, breaker.
type LLMRung struct {
	// Configured is set by the caller; if false, the rung is absent.
	Configured bool
	// Enabled, when set, is read per call: the operator can switch the LLM on
	// and off at runtime (/ctrl/llm), so a rung built at boot must not assume
	// the boot-time setting still holds. Nil means always enabled.
	Enabled func() bool
	// Admit is the bounded queue admission control. Returns false when full.
	Admit func() bool
	// Release is called exactly once after Admit admitted a request, on both
	// success and error paths, to return the queue slot (adversarial review M2).
	Release func()
	// Breaker is the circuit breaker state.
	Breaker *Breaker
	// Provider is the LLM provider client (OpenAI-compatible). When nil the
	// rung reports ErrLLMNotImplemented — configured but not wired.
	Provider interface {
		Complete(ctx context.Context, query string) (string, error)
	}

	// flight collapses identical in-flight queries into one provider call.
	flight flightGroup
}

// Breaker is a circuit breaker. After Threshold consecutive failures it opens
// for Cooldown; then it admits exactly one probe call. The probe's outcome
// closes it again or restarts the cooldown. Everyone else is refused while the
// probe is out, so a still-dead provider sees one request per cooldown rather
// than the whole backlog at once.
type Breaker struct {
	mu      sync.Mutex
	failed  int
	open    bool
	opened  time.Time
	probing bool
	// Threshold opens after this many consecutive failures.
	Threshold int
	// Cooldown is how long the breaker stays open.
	Cooldown time.Duration
}

// breakerOutcome is what a call admitted by the breaker reports back.
type breakerOutcome int

const (
	// outcomeNone: the call never reached the provider, or failed in a way
	// that says nothing about the provider's health (client went away, bad
	// model output). The breaker state is left as it was.
	outcomeNone breakerOutcome = iota
	outcomeSuccess
	outcomeFailure
)

// acquire admits a call. probe is true when this call is the single half-open
// probe; the caller must pass it back to finish.
func (b *Breaker) acquire() (ok, probe bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return true, false
	}
	if b.probing || time.Since(b.opened) < b.Cooldown {
		return false, false
	}
	b.probing = true
	return true, true
}

// finish records a call's outcome. Every call acquire admitted must finish,
// on every path, or a probe slot would be held forever.
func (b *Breaker) finish(probe bool, o breakerOutcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if probe {
		b.probing = false
	}
	switch o {
	case outcomeSuccess:
		b.failed = 0
		b.open = false
	case outcomeFailure:
		b.failed++
		// A failed probe reopens immediately: one more failure is enough
		// evidence that the provider is still down.
		if probe || b.failed >= b.Threshold {
			b.open = true
			b.opened = time.Now()
		}
	}
}

// maxLLMCandidates bounds how many candidates one model reply may contribute,
// whatever the model claims. Each one is a billable row.
const maxLLMCandidates = 20

// llmMaxMatchScore caps an LLM candidate's match_score. Deterministic matches
// score against real data; a model's self-reported confidence does not, so it
// must never read as better than a solid deterministic match.
const llmMaxMatchScore = 0.5

func (r *LLMRung) Try(ctx context.Context, q Query) (string, contract.ResolveResponse, error) {
	if !r.Configured || (r.Enabled != nil && !r.Enabled()) {
		return "", contract.ResolveResponse{}, ErrNoRung
	}
	ok, probe := r.Breaker.acquire()
	if !ok {
		return "", contract.ResolveResponse{}, ErrLLMDegraded
	}
	outcome := outcomeNone
	defer func() { r.Breaker.finish(probe, outcome) }()

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
	// Deadline shedding: if the request already timed out, drop it.
	if ctx.Err() != nil {
		return "", contract.ResolveResponse{}, ctx.Err()
	}
	if r.Provider == nil {
		return "", contract.ResolveResponse{}, ErrLLMNotImplemented
	}
	// Count the call against the caller's LLM budget before spending it. Each
	// caller pays for the answer it gets, even when an identical in-flight
	// query below saves the provider call: the cap bounds what one caller can
	// draw from the LLM rung, and whether a stranger asked the same thing at
	// the same moment must not change that.
	if g.Charge != nil {
		if err := g.Charge(); err != nil {
			return "", contract.ResolveResponse{}, err
		}
	}

	// Singleflight: concurrent identical queries share one provider call.
	key := hashQuery(q.Raw)
	var resp contract.ResolveResponse
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var shared bool
		resp, err, shared = r.flight.do(ctx, key, func() (contract.ResolveResponse, error) {
			res, err := r.callLLM(ctx, q)
			outcome = r.classify(ctx, err)
			return res, err
		})
		// The call we joined belonged to a request that was cancelled or
		// timed out on its own clock. That says nothing about ours: run again
		// while our own deadline allows.
		if shared && ctx.Err() == nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			continue
		}
		break
	}
	if err != nil {
		return "", contract.ResolveResponse{}, err
	}
	// The response may be shared with other callers: copy before trimming to
	// this caller's limit.
	cands := append([]contract.Candidate(nil), resp.Candidates...)
	if n := q.limit(maxLLMCandidates); len(cands) > n {
		cands = cands[:n]
		resp.Truncated = true
	}
	resp.Candidates = cands
	return StrategyLLM, resp, nil
}

// classify maps a provider call's error to a breaker outcome. Only failures
// that say the provider is unhealthy count against it. Bad model output in
// particular must not: a caller can provoke it on purpose (prompt injection),
// and it would then be able to open the breaker for everyone.
func (r *LLMRung) classify(ctx context.Context, err error) breakerOutcome {
	switch {
	case err == nil, errors.Is(err, ErrLLMBadOutput):
		return outcomeSuccess
	case errors.Is(err, context.Canceled) && ctx.Err() != nil:
		return outcomeNone // our client went away; the provider is not at fault
	case r.Enabled != nil && !r.Enabled():
		return outcomeNone // switched off mid-call
	default:
		return outcomeFailure
	}
}

// flightGroup runs one call per key among concurrent callers. Unlike a
// check-then-store map, the entry is registered before the call starts, so a
// second caller arriving mid-call waits for the first one's result.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flightCall
}

type flightCall struct {
	done chan struct{}
	resp contract.ResolveResponse
	err  error
}

var errFlightAborted = errors.New("llm call aborted")

// do runs fn once for key; concurrent callers with the same key wait for that
// result. shared reports whether the result came from another caller's call.
// A waiting caller gives up when its own ctx ends. The entry is removed as
// soon as the call returns, so the map holds only in-flight keys.
func (g *flightGroup) do(ctx context.Context, key string, fn func() (contract.ResolveResponse, error)) (resp contract.ResolveResponse, err error, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*flightCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.resp, c.err, true
		case <-ctx.Done():
			return contract.ResolveResponse{}, ctx.Err(), true
		}
	}
	c := &flightCall{done: make(chan struct{}), err: errFlightAborted}
	g.m[key] = c
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		close(c.done)
	}()
	c.resp, c.err = fn()
	return c.resp, c.err, false
}

// callLLM is the seam — the real LLM call. With a provider the query is sent
// to the OpenAI-compatible endpoint and the model's JSON output is parsed into
// a ResolveResponse.
func (r *LLMRung) callLLM(ctx context.Context, q Query) (contract.ResolveResponse, error) {
	if r.Provider == nil {
		return contract.ResolveResponse{}, ErrLLMNotImplemented
	}
	raw, err := r.Provider.Complete(ctx, q.Raw)
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	resp, err := parseLLMReply(raw)
	if err != nil {
		return contract.ResolveResponse{}, err
	}
	// The model output is untrusted (adversarial review C2): a prompt-injection
	// into the model can yield arbitrary text, invented identifiers and
	// out-of-bounds coordinates. Sanitize every candidate before it reaches
	// the caller.
	sanitizeLLMCandidates(&resp)
	return resp, nil
}

// parseLLMReply extracts the JSON object from a model reply. Models asked for
// "JSON only" still wrap it in ```json fences or add a sentence before or
// after; that is a usable answer, not a failure. The first '{' from which a
// complete JSON object decodes wins; anything after it is ignored.
func parseLLMReply(raw string) (contract.ResolveResponse, error) {
	s := raw
	for tries := 0; tries < 8; tries++ {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			break
		}
		s = s[i:]
		var resp contract.ResolveResponse
		if err := json.NewDecoder(strings.NewReader(s)).Decode(&resp); err == nil {
			return resp, nil
		}
		s = s[1:]
	}
	return contract.ResolveResponse{}, ErrLLMBadOutput
}

// sanitizeLLMCandidates strips untrusted model output down to what the model
// can honestly contribute: a point and a description. The model is not a
// data source. Anything that would make its answer pass for authoritative
// data — a G-NAF source or PID, G-NAF quality fields, a dataset version, a
// match score above what deterministic matching earns — is overwritten, so a
// consumer can always tell a model guess from a G-NAF or OSM record.
func sanitizeLLMCandidates(resp *contract.ResolveResponse) {
	out := resp.Candidates[:0]
	for _, c := range resp.Candidates {
		// Clamp coordinates to the AU bbox (mirrors the coord rung's T4 check).
		if c.Point.Lat < -60 || c.Point.Lat > -9 || c.Point.Lon < 110 || c.Point.Lon > 160 {
			continue // drop out-of-scope candidate
		}
		if c.Kind != contract.KindPOI {
			c.Kind = contract.KindAddress
		}
		c.Source = StrategyLLM
		c.ID = contract.CandidateID{Source: StrategyLLM}
		c.GnafPID = ""
		c.GnafConfidence = 0
		c.GeocodeReliability = 0
		// contract.Precision has no "approximate" value; empty is the honest
		// answer for a model-inferred point (it claims no particular extent).
		c.Precision = ""
		c.LocalityID = 0
		c.DistanceM = nil
		switch {
		case !(c.MatchScore > 0): // also catches NaN
			c.MatchScore = 0
		case c.MatchScore > llmMaxMatchScore:
			c.MatchScore = llmMaxMatchScore
		}
		// Strip markup from free-text fields so a downstream consumer
		// rendering them as HTML is not XSS-vulnerable.
		c.Text = stripMarkup(c.Text)
		c.Name = stripMarkup(c.Name)
		c.Brand = stripMarkup(c.Brand)
		c.Operator = stripMarkup(c.Operator)
		out = append(out, c)
		if len(out) == maxLLMCandidates {
			break
		}
	}
	resp.Candidates = out
	// Response-level fields describe a dataset query; none happened.
	resp.Truncated = false
	resp.TotalMatched = len(out)
	resp.GeneratedCount = len(out)
	resp.DatasetVersion = ""
	resp.Ambiguous = nil
	resp.Degraded = nil
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

// ErrLLMBadOutput is returned when the provider answered but no JSON object
// could be read from the reply. The rung is wired and the provider is up; the
// upstream's answer was unusable (a bad gateway, not a missing feature).
var ErrLLMBadOutput = errors.New("llm reply not usable")

// ErrQueueFull is returned when the LLM queue is at capacity.
var ErrQueueFull = errors.New("llm queue full")

func hashQuery(raw string) string {
	// FNV-1a (64-bit) of the raw query, in-memory only (D-015: never
	// persisted/logged). The hash is a dedupe key for in-flight calls, not a
	// retention mechanism. It is not collision-resistant, and need not be: a
	// collision only merges two concurrent calls, among the handful of
	// queries in flight at any moment.
	h := fnv.New64a()
	_, _ = h.Write([]byte(raw))
	return strconv.FormatUint(h.Sum64(), 16)
}
