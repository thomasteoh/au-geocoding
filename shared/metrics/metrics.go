// Package metrics is a minimal in-memory Prometheus-style collector shared by
// the au-places and au-geocoding servers. It records per-endpoint/status
// counters and a latency histogram, and renders Prometheus text exposition
// (format 0.0.4) on demand. No external dependency.
//
// INV-1 holds: no query-derived label ever exists. Only endpoint, status, and
// latency are recorded, never query text. Endpoint labels come from a fixed
// set: callers pass route patterns (never raw request paths), the collector
// can be given an allowlist, and a hard cardinality cap folds anything beyond
// it into OtherEndpoint so a misbehaving caller cannot grow memory unbounded.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Buckets are the latency histogram upper bounds in milliseconds. Each bucket
// counts observations <= its bound (Prometheus `le` semantics); the implicit
// final bucket is +Inf.
var Buckets = []int64{10, 50, 100, 250, 500, 1000, 2000, 5000}

// NumBuckets is the histogram size: one per bucket bound plus the +Inf bucket.
// It must be len(Buckets)+1. Kept as a constant because Go array lengths must
// be constant expressions.
const NumBuckets = 9

// OtherEndpoint is the label used for any endpoint outside the allowlist or
// beyond MaxEndpoints.
const OtherEndpoint = "other"

// MaxEndpoints caps the number of distinct endpoint labels a collector will
// track. Endpoints first seen after the cap is reached are recorded as
// OtherEndpoint.
const MaxEndpoints = 64

// histogram holds per-bucket (non-cumulative) counts; the last slot is +Inf.
// Render accumulates them, as the exposition format requires.
type histogram [NumBuckets]int64

type reqKey struct {
	endpoint string
	status   string
}

// Collector records request counters and latency. prefix names the metrics
// (e.g. "augeo" or "auplaces") so multiple services can be scraped distinctly.
type Collector struct {
	mu        sync.Mutex
	prefix    string
	allowed   map[string]bool // nil => any endpoint, subject to MaxEndpoints
	endpoints map[string]bool // distinct endpoint labels seen so far
	requests  map[reqKey]*reqCounter
	latency   histogram
	sumMS     int64
	total     int64
}

type reqCounter struct {
	resultSum int64
	count     int64
}

// New builds an empty collector. prefix names the metrics (e.g. "augeo").
// endpoints, when given, is the complete set of endpoint labels; anything else
// is recorded as OtherEndpoint.
func New(prefix string, endpoints ...string) *Collector {
	c := &Collector{
		prefix:    prefix,
		endpoints: make(map[string]bool),
		requests:  make(map[reqKey]*reqCounter),
	}
	if len(endpoints) > 0 {
		c.allowed = make(map[string]bool, len(endpoints))
		for _, e := range endpoints {
			c.allowed[e] = true
		}
	}
	return c
}

// endpointLabel maps a caller-supplied endpoint onto the bounded label set.
// Must be called with m.mu held.
func (m *Collector) endpointLabel(endpoint string) string {
	if m.allowed != nil && !m.allowed[endpoint] {
		return OtherEndpoint
	}
	if m.endpoints[endpoint] {
		return endpoint
	}
	if len(m.endpoints) >= MaxEndpoints {
		return OtherEndpoint
	}
	m.endpoints[endpoint] = true
	return endpoint
}

// statusLabel keeps the status label to valid HTTP codes.
func statusLabel(status int64) string {
	if status < 100 || status > 999 {
		return "other"
	}
	return strconv.FormatInt(status, 10)
}

// Record increments one request. endpoint is the route pattern (never the raw
// request path); status is the HTTP status; latencyMS is the duration in ms;
// resultCount is the number of result rows (0 if the handler doesn't surface
// them).
func (m *Collector) Record(endpoint string, status, latencyMS int64, resultCount int64) {
	if latencyMS < 0 {
		latencyMS = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := reqKey{endpoint: m.endpointLabel(endpoint), status: statusLabel(status)}
	c, ok := m.requests[k]
	if !ok {
		c = &reqCounter{}
		m.requests[k] = c
	}
	c.count++
	c.resultSum += resultCount
	m.total++
	m.sumMS += latencyMS
	// First bucket whose bound is >= the observation; +Inf otherwise.
	b := len(Buckets)
	for i, bound := range Buckets {
		if latencyMS <= bound {
			b = i
			break
		}
	}
	m.latency[b]++
}

// Render writes the Prometheus text exposition to an HTTP response.
func (m *Collector) Render(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = io.WriteString(w, m.Exposition())
}

// Exposition returns the Prometheus text exposition (format 0.0.4).
func (m *Collector) Exposition() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.prefix
	var b strings.Builder
	keys := make([]reqKey, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].endpoint != keys[j].endpoint {
			return keys[i].endpoint < keys[j].endpoint
		}
		return keys[i].status < keys[j].status
	})

	fmt.Fprintf(&b, "# HELP %s_requests_total Requests by endpoint and status.\n", p)
	fmt.Fprintf(&b, "# TYPE %s_requests_total counter\n", p)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s_requests_total{endpoint=\"%s\",status=\"%s\"} %d\n", p, EscapeLabelValue(k.endpoint), EscapeLabelValue(k.status), m.requests[k].count)
	}
	fmt.Fprintf(&b, "# HELP %s_result_rows_total Result rows returned by endpoint and status.\n", p)
	fmt.Fprintf(&b, "# TYPE %s_result_rows_total counter\n", p)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s_result_rows_total{endpoint=\"%s\",status=\"%s\"} %d\n", p, EscapeLabelValue(k.endpoint), EscapeLabelValue(k.status), m.requests[k].resultSum)
	}

	fmt.Fprintf(&b, "# HELP %s_request_latency_ms Request latency in milliseconds.\n", p)
	fmt.Fprintf(&b, "# TYPE %s_request_latency_ms histogram\n", p)
	var cum int64
	for i, v := range m.latency {
		cum += v
		fmt.Fprintf(&b, "%s_request_latency_ms_bucket{le=\"%s\"} %d\n", p, latencyBound(i), cum)
	}
	fmt.Fprintf(&b, "%s_request_latency_ms_sum %d\n", p, m.sumMS)
	fmt.Fprintf(&b, "%s_request_latency_ms_count %d\n", p, m.total)

	fmt.Fprintf(&b, "# HELP %s_requests_processed_total Total requests processed.\n", p)
	fmt.Fprintf(&b, "# TYPE %s_requests_processed_total counter\n", p)
	fmt.Fprintf(&b, "%s_requests_processed_total %d\n", p, m.total)
	return b.String()
}

func latencyBound(i int) string {
	if i < len(Buckets) {
		return strconv.FormatInt(Buckets[i], 10)
	}
	return "+Inf"
}

// EscapeLabelValue escapes a label value for the Prometheus text format:
// backslash, double quote and line feed are the only escapes the format
// defines. Invalid UTF-8 is replaced with U+FFFD, since the format requires
// valid UTF-8 and a scraper rejects the whole page otherwise.
func EscapeLabelValue(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
