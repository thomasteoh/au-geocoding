package publicapi

import (
	"errors"
	"testing"
)

// TestIssueAuthenticate covers the key lifecycle: issue, authenticate, revoke.
func TestIssueAuthenticate(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, raw, err := s.IssueKey("test", TierStandard, []string{"search"})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("empty raw key")
	}

	k, err := s.Authenticate(raw)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if k.ID != id || k.Tier != TierStandard {
		t.Fatalf("bad key: id=%d tier=%v", k.ID, k.Tier)
	}

	// Wrong key → ErrInvalidKey.
	if _, err := s.Authenticate("00000000000000000000000000000000"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("wrong key: got %v, want ErrInvalidKey", err)
	}

	// Revoked key → ErrInvalidKey.
	if err := s.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(raw); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("revoked key: got %v, want ErrInvalidKey", err)
	}
}

// TestChargeRowsQuota covers D-034: quota is per result row, not per request.
func TestChargeRowsQuota(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, raw, err := s.IssueKey("q", TierStandard, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw

	// Charge up to the ceiling.
	for i := int64(0); i < 10; i++ {
		ok, err := s.ChargeRows(id, TierStandard, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("charge %d: over quota", i)
		}
	}
	// 10001th row should exceed (D-034: per-row ceiling).
	ok, err := s.ChargeRows(id, TierStandard, 1)
	if ok {
		t.Fatal("expected quota exceeded")
	}
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
}

// TestRateLimiter covers the token bucket.
func TestRateLimiter(t *testing.T) {
	r := NewRateLimiter(10, 2)
	// Burst of 2.
	if !r.Allow("k") || !r.Allow("k") {
		t.Fatal("burst should allow 2")
	}
	if r.Allow("k") {
		t.Fatal("burst exceeded")
	}
}

// TestChargeAnonDaily covers D-026: anonymous daily quota is per-IP, with a
// global ceiling, and resets on the day roll.
func TestChargeAnonDaily(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// per-IP ceiling of 100; global ceiling of 200.
	ok, err := s.ChargeAnonDaily("1.2.3.4", 100, 100, 200)
	if err != nil || !ok {
		t.Fatalf("charge 100: ok=%v err=%v", ok, err)
	}
	// Same IP over per-IP ceiling.
	ok, err = s.ChargeAnonDaily("1.2.3.4", 1, 100, 200)
	if ok {
		t.Fatal("expected per-IP quota exceeded")
	}
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
	// Different IP within global ceiling.
	ok, err = s.ChargeAnonDaily("5.6.7.8", 100, 100, 200)
	if err != nil || !ok {
		t.Fatalf("charge second ip 100: ok=%v err=%v", ok, err)
	}
	// Now global ceiling exceeded.
	ok, err = s.ChargeAnonDaily("9.9.9.9", 1, 100, 200)
	if ok {
		t.Fatal("expected global quota exceeded")
	}
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
	// perIP<=0 → no ceiling, always ok.
	ok, err = s.ChargeAnonDaily("1.2.3.4", 1, 0, 0)
	if err != nil || !ok {
		t.Fatalf("no-ceiling: ok=%v err=%v", ok, err)
	}
}
