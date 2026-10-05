package publicapi

import (
	"database/sql"
	"errors"
	"testing"
	"time"
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

// TestOrgKeysShareQuotaAndStayScoped covers console keys: an org's keys share
// one daily quota (more keys never means more rows, T1), revocation is
// org-scoped, and expiry is enforced.
func TestOrgKeysShareQuotaAndStayScoped(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	k1, raw1, err := s.IssueKeyWith(IssueOptions{Label: "a", Tier: TierDemo, OrgID: 7, CreatedBy: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, raw2, _ := s.IssueKeyWith(IssueOptions{Label: "b", Tier: TierDemo, OrgID: 7, CreatedBy: 1})
	a1, err := s.Authenticate(raw1)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := s.Authenticate(raw2)
	p1, p2 := KeyPrincipal(a1), KeyPrincipal(a2)
	if p1.UsageKey != "org:7" || p1.UsageKey != p2.UsageKey || p1.RateKey == p2.RateKey {
		t.Fatalf("principals: %+v %+v", p1, p2)
	}
	if ok, _ := s.ChargePrincipal(p1, TierQuota[TierDemo]); !ok {
		t.Fatal("first key should fill the quota")
	}
	if ok, _ := s.ChargePrincipal(p2, 1); ok {
		t.Fatal("second key got its own quota")
	}
	if n, _ := s.UsageToday("org:7"); n != TierQuota[TierDemo] {
		t.Fatalf("usage today = %d", n)
	}

	// Revocation is scoped to the owning org.
	if err := s.RevokeOrgKey(8, k1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org revoke: %v", err)
	}
	if err := s.RevokeOrgKey(7, k1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(raw1); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("revoked org key still authenticates")
	}
	keys, _ := s.OrgKeys(7)
	if len(keys) != 2 || keys[0].Hash != [32]byte{} {
		t.Fatalf("OrgKeys: %+v", keys)
	}

	// Expired keys are rejected with the same error.
	past := time.Now().Add(-time.Minute)
	_, raw3, _ := s.IssueKeyWith(IssueOptions{Label: "c", Tier: TierDemo, OrgID: 7, Expires: &past})
	if _, err := s.Authenticate(raw3); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("expired key authenticates")
	}

	// Tier changes reach live keys.
	if err := s.SetOrgTier(7, TierBatch); err != nil {
		t.Fatal(err)
	}
	if a2, _ = s.Authenticate(raw2); a2.Tier != TierBatch {
		t.Fatalf("tier after change = %v", a2.Tier)
	}

	// The index survives a reopen (fields round-trip through scanKey).
	path := t.TempDir() + "/re.db"
	s2, _ := Open(path)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	_, raw4, _ := s2.IssueKeyWith(IssueOptions{Label: "d", Tier: TierStandard, OrgID: 9, CreatedBy: 3, Expires: &exp})
	s2.Close()
	s3, _ := Open(path)
	defer s3.Close()
	k4, err := s3.Authenticate(raw4)
	if err != nil || k4.OrgID != 9 || k4.CreatedBy != 3 || k4.Expires == nil || !k4.Expires.Equal(exp) {
		t.Fatalf("reopened key: %+v %v", k4, err)
	}
}

// TestLegacyUsageMigrated covers the move from per-key usage rows to
// principal rows: today's spend survives the upgrade.
func TestLegacyUsageMigrated(t *testing.T) {
	path := t.TempDir() + "/app.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Format("2006-01-02")
	for _, q := range []string{
		`CREATE TABLE usage (key_id INTEGER NOT NULL, day TEXT NOT NULL, rows INTEGER NOT NULL DEFAULT 0, llm_calls INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (key_id, day))`,
		`INSERT INTO usage VALUES (5, '` + day + `', 42, 0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n, _ := s.UsageToday("key:5"); n != 42 {
		t.Fatalf("migrated usage = %d", n)
	}
}
