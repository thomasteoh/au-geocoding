package metrics

import (
	"bufio"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// sample is one parsed exposition sample line.
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

var metricNameOK = func(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		ok := r == '_' || r == ':' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// parseExposition is a strict-enough parser for the Prometheus text format
// (0.0.4): HELP/TYPE comments, samples with escaped label values, and a TYPE
// declared at most once per family and before its samples.
func parseExposition(t *testing.T, text string) ([]sample, map[string]string) {
	t.Helper()
	if !utf8.ValidString(text) {
		t.Fatalf("exposition is not valid UTF-8")
	}
	types := map[string]string{}
	var out []sample
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[1] == "TYPE" {
				if len(f) != 4 {
					t.Fatalf("line %d: bad TYPE: %q", n, line)
				}
				if _, dup := types[f[2]]; dup {
					t.Fatalf("line %d: duplicate TYPE for %s", n, f[2])
				}
				switch f[3] {
				case "counter", "gauge", "histogram", "summary", "untyped":
				default:
					t.Fatalf("line %d: bad type %q", n, f[3])
				}
				types[f[2]] = f[3]
			}
			continue
		}
		s := sample{labels: map[string]string{}}
		i := strings.IndexAny(line, "{ ")
		if i < 0 {
			t.Fatalf("line %d: no value: %q", n, line)
		}
		s.name = line[:i]
		if !metricNameOK(s.name) {
			t.Fatalf("line %d: bad metric name %q", n, s.name)
		}
		rest := line[i:]
		if rest[0] == '{' {
			rest = rest[1:]
			for {
				if strings.HasPrefix(rest, "}") {
					rest = rest[1:]
					break
				}
				eq := strings.IndexByte(rest, '=')
				if eq < 0 || len(rest) < eq+2 || rest[eq+1] != '"' {
					t.Fatalf("line %d: bad label: %q", n, line)
				}
				ln := rest[:eq]
				if !metricNameOK(ln) {
					t.Fatalf("line %d: bad label name %q", n, ln)
				}
				rest = rest[eq+2:]
				var v strings.Builder
				closed := false
				for j := 0; j < len(rest); j++ {
					c := rest[j]
					if c == '\\' {
						if j+1 >= len(rest) {
							t.Fatalf("line %d: dangling escape", n)
						}
						switch rest[j+1] {
						case '\\':
							v.WriteByte('\\')
						case '"':
							v.WriteByte('"')
						case 'n':
							v.WriteByte('\n')
						default:
							t.Fatalf("line %d: invalid escape \\%c", n, rest[j+1])
						}
						j++
						continue
					}
					if c == '"' {
						rest = rest[j+1:]
						closed = true
						break
					}
					v.WriteByte(c)
				}
				if !closed {
					t.Fatalf("line %d: unterminated label value", n)
				}
				s.labels[ln] = v.String()
				rest = strings.TrimPrefix(rest, ",")
			}
		}
		if !strings.HasPrefix(rest, " ") {
			t.Fatalf("line %d: missing space before value: %q", n, line)
		}
		val, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
		if err != nil {
			t.Fatalf("line %d: bad value: %v", n, err)
		}
		s.value = val
		family := s.name
		for _, suf := range []string{"_bucket", "_sum", "_count"} {
			if b := strings.TrimSuffix(s.name, suf); b != s.name && types[b] == "histogram" {
				family = b
			}
		}
		if _, ok := types[family]; !ok {
			t.Fatalf("line %d: sample %s before/without TYPE", n, s.name)
		}
		out = append(out, s)
	}
	return out, types
}

func TestExpositionParses(t *testing.T) {
	m := New("svc")
	m.Record("/search", 200, 5, 3)
	m.Record("/search", 200, 10, 1)
	m.Record("/search", 500, 120, 0)
	m.Record("/suggest", 200, 9999, 2)
	samples, types := parseExposition(t, m.Exposition())
	if types["svc_request_latency_ms"] != "histogram" {
		t.Fatalf("latency TYPE = %q", types["svc_request_latency_ms"])
	}
	got := map[string]float64{}
	for _, s := range samples {
		got[fmt.Sprintf("%s%v", s.name, s.labels)] = s.value
	}
	for k, want := range map[string]float64{
		"svc_requests_total" + fmt.Sprint(map[string]string{"endpoint": "/search", "status": "200"}):    2,
		"svc_result_rows_total" + fmt.Sprint(map[string]string{"endpoint": "/search", "status": "200"}): 4,
		"svc_request_latency_ms_sum" + fmt.Sprint(map[string]string{}):                                  10134,
		"svc_request_latency_ms_count" + fmt.Sprint(map[string]string{}):                                4,
		"svc_requests_processed_total" + fmt.Sprint(map[string]string{}):                                4,
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
}

func TestHistogramCumulative(t *testing.T) {
	m := New("svc")
	// 10 lands in le="10" (inclusive); 11 in le="50"; 5000 in le="5000";
	// 5001 only in +Inf.
	for _, ms := range []int64{0, 10, 11, 50, 5000, 5001} {
		m.Record("/x", 200, ms, 0)
	}
	samples, _ := parseExposition(t, m.Exposition())
	var les []string
	var vals []float64
	var count float64
	for _, s := range samples {
		switch s.name {
		case "svc_request_latency_ms_bucket":
			les = append(les, s.labels["le"])
			vals = append(vals, s.value)
		case "svc_request_latency_ms_count":
			count = s.value
		}
	}
	wantLE := []string{"10", "50", "100", "250", "500", "1000", "2000", "5000", "+Inf"}
	wantV := []float64{2, 4, 4, 4, 4, 4, 4, 5, 6}
	if fmt.Sprint(les) != fmt.Sprint(wantLE) || fmt.Sprint(vals) != fmt.Sprint(wantV) {
		t.Fatalf("buckets le=%v vals=%v; want %v %v", les, vals, wantLE, wantV)
	}
	for i := 1; i < len(vals); i++ {
		if vals[i] < vals[i-1] {
			t.Fatalf("buckets not cumulative: %v", vals)
		}
	}
	if vals[len(vals)-1] != count {
		t.Fatalf("+Inf bucket %v != count %v", vals[len(vals)-1], count)
	}
}

func TestLabelEscaping(t *testing.T) {
	nasty := "/a\"b\\c\nd\xffe"
	m := New("svc")
	m.Record(nasty, 200, 1, 0)
	samples, _ := parseExposition(t, m.Exposition())
	found := false
	for _, s := range samples {
		if s.name == "svc_requests_total" {
			found = true
			if want := "/a\"b\\c\nd�e"; s.labels["endpoint"] != want {
				t.Fatalf("endpoint round-trip = %q, want %q", s.labels["endpoint"], want)
			}
		}
	}
	if !found {
		t.Fatal("no requests_total sample")
	}
	if got := EscapeLabelValue("a\tb"); got != "a\tb" {
		t.Fatalf("tab must not be escaped: %q", got)
	}
}

func TestEndpointAllowlist(t *testing.T) {
	m := New("svc", "/search")
	m.Record("/search", 200, 1, 0)
	m.Record("/random/path", 404, 1, 0)
	out := m.Exposition()
	if strings.Contains(out, "/random/path") {
		t.Fatalf("unlisted endpoint leaked into labels:\n%s", out)
	}
	if !strings.Contains(out, `svc_requests_total{endpoint="other",status="404"} 1`) {
		t.Fatalf("unlisted endpoint not folded into other:\n%s", out)
	}
}

func TestEndpointCardinalityCap(t *testing.T) {
	m := New("svc")
	for i := 0; i < MaxEndpoints*4; i++ {
		m.Record(fmt.Sprintf("/p/%d", i), 200, 1, 0)
	}
	m.Record("/p/0", 200, 1, 0) // already tracked: keeps its own label
	m.mu.Lock()
	n := len(m.requests)
	m.mu.Unlock()
	if n != MaxEndpoints+1 {
		t.Fatalf("series = %d, want %d (cap + other)", n, MaxEndpoints+1)
	}
	out := m.Exposition()
	if !strings.Contains(out, `svc_requests_total{endpoint="/p/0",status="200"} 2`) {
		t.Fatalf("tracked endpoint lost:\n%s", out)
	}
	parseExposition(t, out)
}

func TestRenderContentType(t *testing.T) {
	m := New("svc")
	rec := httptest.NewRecorder()
	m.Render(rec)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	parseExposition(t, rec.Body.String())
}

func TestGolden(t *testing.T) {
	m := New("g")
	m.Record("/a", 200, 7, 2)
	want := `# HELP g_requests_total Requests by endpoint and status.
# TYPE g_requests_total counter
g_requests_total{endpoint="/a",status="200"} 1
# HELP g_result_rows_total Result rows returned by endpoint and status.
# TYPE g_result_rows_total counter
g_result_rows_total{endpoint="/a",status="200"} 2
# HELP g_request_latency_ms Request latency in milliseconds.
# TYPE g_request_latency_ms histogram
g_request_latency_ms_bucket{le="10"} 1
g_request_latency_ms_bucket{le="50"} 1
g_request_latency_ms_bucket{le="100"} 1
g_request_latency_ms_bucket{le="250"} 1
g_request_latency_ms_bucket{le="500"} 1
g_request_latency_ms_bucket{le="1000"} 1
g_request_latency_ms_bucket{le="2000"} 1
g_request_latency_ms_bucket{le="5000"} 1
g_request_latency_ms_bucket{le="+Inf"} 1
g_request_latency_ms_sum 7
g_request_latency_ms_count 1
# HELP g_requests_processed_total Total requests processed.
# TYPE g_requests_processed_total counter
g_requests_processed_total 1
`
	if got := m.Exposition(); got != want {
		t.Fatalf("exposition mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}
