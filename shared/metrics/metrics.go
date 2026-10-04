// Package metrics is a minimal in-memory Prometheus-style collector shared by
// the au-places and au-geocoding servers. It records per-endpoint/status
// counters and a latency histogram, and renders Prometheus text exposition on
// demand. No external dependency.
//
// INV-1 holds: no query-derived label ever exists. Only endpoint, status, and
// latency are recorded — never query text.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Buckets are the latency histogram bounds in milliseconds. The final bucket
// is +Inf; the array MUST have exactly len(Buckets)+1 entries (the +Inf bucket
// is index len(Buckets)). A longer array renders duplicate le="+Inf" lines,
// which Prometheus scrapers reject.
var Buckets = []int64{10, 50, 100, 250, 500, 1000, 2000, 5000}

// NumBuckets is the histogram size: one per bucket bound plus the +Inf bucket.
// It must be len(Buckets)+1. Kept as a constant because Go array lengths must
// be constant expressions.
const NumBuckets = 9

// histogram is a fixed-size latency histogram. The last slot is +Inf.
type histogram [NumBuckets]int64

// Collector records request counters and latency. prefix names the metrics
// (e.g. "augeo" or "auplaces") so multiple services can be scraped distinctly.
type Collector struct {
	mu       sync.Mutex
	prefix   string
	requests map[string]*reqCounter // endpoint/status → counters
	latency  histogram
	total    int64
}

type reqCounter struct {
	status    int
	resultSum int64
	count     int64
}

// New builds an empty collector. prefix names the metrics (e.g. "augeo").
func New(prefix string) *Collector {
	return &Collector{prefix: prefix, requests: make(map[string]*reqCounter)}
}

// Record increments one request. endpoint is the route; status is the HTTP
// status; latency is the duration in ms; resultCount is the number of result
// rows (0 if the handler doesn't surface them).
func (m *Collector) Record(endpoint string, status, latencyMS int64, resultCount int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := endpoint + "/" + strconv.FormatInt(status, 10)
	c, ok := m.requests[k]
	if !ok {
		c = &reqCounter{status: int(status)}
		m.requests[k] = c
	}
	c.count++
	c.resultSum += resultCount
	m.total++
	// Bucket the latency. The last bucket (index len(Buckets)) is +Inf.
	b := int64(0)
	for i, bound := range Buckets {
		if latencyMS < bound {
			b = int64(i)
			break
		}
	}
	if latencyMS >= Buckets[len(Buckets)-1] {
		b = int64(len(Buckets))
	}
	if b < int64(len(m.latency)) {
		m.latency[b]++
	}
}

// Render writes the Prometheus text exposition.
func (m *Collector) Render(w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s metrics — counters and histograms only, no query-derived labels\n", m.prefix))
	// Deterministic order.
	keys := make([]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := m.requests[k]
		ep, st := splitEndpointStatus(k)
		fmt.Fprintf(&b, "%s_requests_total{endpoint=%q,status=%q} %d\n", m.prefix, ep, st, c.count)
		if c.resultSum > 0 || true { // always emit; 0 is valid
			fmt.Fprintf(&b, "%s_result_rows_total{endpoint=%q,status=%q} %d\n", m.prefix, ep, st, c.resultSum)
		}
	}
	b.WriteString(fmt.Sprintf("# HELP %s_request_latency_ms_bucket Latency histogram.\n", m.prefix))
	b.WriteString(fmt.Sprintf("# TYPE %s_request_latency_ms_bucket counter\n", m.prefix))
	for i, v := range m.latency {
		bound := latencyBound(int64(i))
		fmt.Fprintf(&b, "%s_request_latency_ms_bucket{le=%q} %d\n", m.prefix, bound, v)
	}
	b.WriteString(fmt.Sprintf("# HELP %s_requests_processed_total Total requests processed.\n", m.prefix))
	b.WriteString(fmt.Sprintf("# TYPE %s_requests_processed_total counter\n", m.prefix))
	fmt.Fprintf(&b, "%s_requests_processed_total %d\n", m.prefix, m.total)
	_, _ = w.Write([]byte(b.String()))
}

func latencyBound(b int64) string {
	if b < int64(len(Buckets)) {
		return strconv.FormatInt(Buckets[b], 10)
	}
	return "+Inf"
}

func splitEndpointStatus(k string) (string, string) {
	i := strings.LastIndexByte(k, '/')
	if i < 0 {
		return k, ""
	}
	return k[:i], k[i+1:]
}

// recordRequest is a convenience for the middleware: it times the request and
// records it. Kept minimal so each server's middleware stays its own shape.
func (m *Collector) recordRequest(start time.Time, endpoint string, status int64, resultCount int64) {
	m.Record(endpoint, status, time.Since(start).Milliseconds(), resultCount)
}
