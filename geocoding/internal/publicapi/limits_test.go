package publicapi

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestAnonCounterRunningTotalAndZeroRows(t *testing.T) {
	c := newAnonCounter(10)
	if !c.charge("a", 0, 5, 100) || c.len() != 0 {
		t.Fatalf("0-row charge inserted an entry (len %d)", c.len())
	}
	for i := 0; i < 5; i++ {
		ip := strconv.Itoa(i)
		if !c.charge(ip, 3, 5, 10) && i < 3 {
			t.Fatalf("charge %d refused", i)
		}
	}
	// 3+3+3 = 9 charged, the 4th (3 more) would exceed the global 10.
	if c.total != 9 {
		t.Fatalf("running total %d, want 9", c.total)
	}
	if !c.atCeiling("new", 5, 9) {
		t.Fatal("global at 9/9 should be at ceiling")
	}
	// Day roll resets the total.
	c.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if !c.charge("0", 5, 5, 10) || c.total != 5 {
		t.Fatalf("after roll: total %d", c.total)
	}
}

func TestAnonCounterFullTableFailsClosed(t *testing.T) {
	c := newAnonCounter(3)
	for i := 0; i < 3; i++ {
		if !c.charge(strconv.Itoa(i), 1, 5, 0) {
			t.Fatalf("charge %d refused", i)
		}
	}
	if c.charge("new", 1, 5, 0) {
		t.Fatal("new IP admitted into a full table")
	}
	if !c.atCeiling("new", 5, 0) {
		t.Fatal("pre-flight should refuse a new IP into a full table")
	}
	// Known IPs keep working; the table never grows.
	if !c.charge("1", 1, 5, 0) || c.len() != 3 {
		t.Fatalf("known IP refused or table grew: %d", c.len())
	}
}

func TestChargeAnonLLMCaps(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.ChargeAnonLLM("a", 0, 100) || s.ChargeAnonLLM("a", 10, 0) {
		t.Fatal("zero caps must turn anonymous LLM off")
	}
	for i := 0; i < 2; i++ {
		if !s.ChargeAnonLLM("a", 2, 3) {
			t.Fatalf("call %d refused", i)
		}
	}
	if s.ChargeAnonLLM("a", 2, 3) {
		t.Fatal("per-IP LLM cap not enforced")
	}
	if !s.ChargeAnonLLM("b", 2, 3) || s.ChargeAnonLLM("c", 2, 3) {
		t.Fatal("global LLM cap not enforced")
	}
}

func TestChargeLLMCallTierCap(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := TierLLMQuota[TierDemo]
	TierLLMQuota[TierDemo] = 2
	defer func() { TierLLMQuota[TierDemo] = old }()
	p := Principal{Kind: "key", Tier: TierDemo, UsageKey: "org:9"}
	for i := 0; i < 2; i++ {
		if err := s.ChargeLLMCall(p); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if err := s.ChargeLLMCall(p); err != ErrLLMQuotaExceeded {
		t.Fatalf("third call: %v", err)
	}
	if n, _ := s.LLMCallsToday("org:9"); n != 2 {
		t.Fatalf("llm_calls = %d", n)
	}
	if rows, _ := s.UsageToday("org:9"); rows != 0 {
		t.Fatalf("LLM counting touched rows: %d", rows)
	}
	if err := s.ChargeLLMCall(Principal{Kind: "anonymous"}); err == nil {
		t.Fatal("anonymous must not use the keyed LLM path")
	}
}

func TestQuotaRemaining(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := Principal{Kind: "key", Tier: TierDemo, UsageKey: "key:1"}
	if left, _ := s.QuotaRemaining(p); left != TierQuota[TierDemo] {
		t.Fatalf("fresh: %d", left)
	}
	if ok, _ := s.ChargePrincipal(p, TierQuota[TierDemo]); !ok {
		t.Fatal("charge to ceiling refused")
	}
	if left, _ := s.QuotaRemaining(p); left != 0 {
		t.Fatalf("at ceiling: %d", left)
	}
	// A zero-row charge never creates a usage row.
	q := Principal{Kind: "key", Tier: TierDemo, UsageKey: "key:2"}
	if ok, _ := s.ChargePrincipal(q, 0); !ok {
		t.Fatal("0-row charge refused")
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM usage_principal WHERE principal='key:2'`).Scan(&n)
	if n != 0 {
		t.Fatal("0-row charge inserted a usage row")
	}
}

func TestRateLimiterLRUBounded(t *testing.T) {
	r := NewRateLimiter(1, 1)
	r.maxKeys = 3
	for _, k := range []string{"a", "b", "c"} {
		r.Allow(k)
	}
	r.Allow("a") // a is now most recent; b is least
	r.Allow("d") // evicts b
	if r.Len() != 3 {
		t.Fatalf("len %d", r.Len())
	}
	if _, ok := r.keys["b"]; ok {
		t.Fatal("LRU entry b not evicted")
	}
	if _, ok := r.keys["a"]; !ok {
		t.Fatal("recently used a evicted")
	}
	// a's bucket survived, so it is still drained.
	if r.Allow("a") {
		t.Fatal("a's bucket was reset")
	}
}

func TestSetOrgTierStripsBatchScope(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	both, rawBoth, _ := s.IssueKeyWith(IssueOptions{Label: "both", Tier: TierBatch, OrgID: 5, Scopes: []string{"search", "batch"}})
	only, rawOnly, _ := s.IssueKeyWith(IssueOptions{Label: "only", Tier: TierBatch, OrgID: 5, Scopes: []string{"batch"}})
	other, _, _ := s.IssueKeyWith(IssueOptions{Label: "other", Tier: TierBatch, OrgID: 6, Scopes: []string{"batch"}})

	ctx := context.Background()
	tx, _ := s.db.BeginTx(ctx, nil)
	if err := s.SetOrgTierTx(ctx, tx, 5, TierStandard); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s.ApplyOrgTier(5, TierStandard)

	check := func(id int64, raw, want string) {
		t.Helper()
		k, _ := s.OrgKey(map[int64]int64{both.ID: 5, only.ID: 5, other.ID: 6}[id], id)
		if got := fmt.Sprint(k.Scopes); got != want {
			t.Fatalf("table key %d scopes %s, want %s", id, got, want)
		}
		if raw != "" {
			a, _ := s.Authenticate(raw)
			if got := fmt.Sprint(a.Scopes); got != want {
				t.Fatalf("index key %d scopes %s, want %s", id, got, want)
			}
		}
	}
	check(both.ID, rawBoth, "[search]")
	// A batch-only key must not fall back to the empty-scope search default.
	check(only.ID, rawOnly, "[none]")
	check(other.ID, "", "[batch]")

	// The non-tx path does the same.
	if err := s.SetOrgTier(6, TierDemo); err != nil {
		t.Fatal(err)
	}
	check(other.ID, "", "[none]")
}

// BenchmarkRateLimiterAtCapacity shows Allow stays O(1) when every request
// is a new key and the limiter is full (each call evicts).
func BenchmarkRateLimiterAtCapacity(b *testing.B) {
	for _, size := range []int{1000, 100000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			r := NewRateLimiter(1, 1)
			r.maxKeys = size
			for i := 0; i < size; i++ {
				r.Allow("seed" + strconv.Itoa(i))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.Allow("k" + strconv.Itoa(i))
			}
		})
	}
}

// BenchmarkChargeAnonDaily shows a charge is O(1) in the number of IPs seen.
func BenchmarkChargeAnonDaily(b *testing.B) {
	for _, ips := range []int{100, 100000} {
		b.Run(strconv.Itoa(ips), func(b *testing.B) {
			c := newAnonCounter(ips)
			for i := 0; i < ips; i++ {
				c.charge(strconv.Itoa(i), 1, 1<<40, 0)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.charge(strconv.Itoa(i%ips), 1, 1<<40, 0)
			}
		})
	}
}
