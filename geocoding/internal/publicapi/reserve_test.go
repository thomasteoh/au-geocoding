package publicapi

import (
	"errors"
	"testing"
)

func TestReserveRowsGrantsWhatIsLeft(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, raw, err := s.IssueKey("t", TierDemo, nil)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := s.Authenticate(raw)
	p := KeyPrincipal(k)
	quota := TierQuota[TierDemo]
	if ok, err := s.ChargePrincipal(p, quota-5); !ok || err != nil {
		t.Fatalf("charge: %v %v", ok, err)
	}
	// 20 wanted, 5 left: the grant is 5, and it is already counted.
	g, err := s.ReserveRows(p, 20)
	if err != nil || g != 5 {
		t.Fatalf("reserve: %d %v", g, err)
	}
	if used, _ := s.UsageToday(p.UsageKey); used != quota {
		t.Fatalf("usage after reserve: %d", used)
	}
	// Nothing left: a zero grant, not an error.
	if g, err := s.ReserveRows(p, 1); g != 0 || err != nil {
		t.Fatalf("reserve at ceiling: %d %v", g, err)
	}
	// Settling returns the unused part.
	if err := s.RefundRows(p, 3); err != nil {
		t.Fatal(err)
	}
	if used, _ := s.UsageToday(p.UsageKey); used != quota-3 {
		t.Fatalf("usage after refund: %d", used)
	}
	// A refund larger than the count never goes negative.
	if err := s.RefundRows(p, 10*quota); err != nil {
		t.Fatal(err)
	}
	if used, _ := s.UsageToday(p.UsageKey); used != 0 {
		t.Fatalf("usage after over-refund: %d", used)
	}
}

// A store fault is an error, never a quiet "no quota".
func TestReserveRowsStoreFault(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	_, raw, _ := s.IssueKey("t", TierDemo, nil)
	k, _ := s.Authenticate(raw)
	s.Close()
	if _, err := s.ReserveRows(KeyPrincipal(k), 1); err == nil {
		t.Fatal("reserve on a closed store reported no error")
	}
	if ok, err := s.ChargePrincipal(KeyPrincipal(k), 1); ok || err == nil {
		t.Fatalf("charge on a closed store: %v %v", ok, err)
	}
}

func TestReserveAnonRows(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if g := s.ReserveAnonRows("192.0.2.1", 20, 30, 100); g != 20 {
		t.Fatalf("first: %d", g)
	}
	if g := s.ReserveAnonRows("192.0.2.1", 20, 30, 100); g != 10 {
		t.Fatalf("second, 10 left per IP: %d", g)
	}
	if g := s.ReserveAnonRows("192.0.2.1", 1, 30, 100); g != 0 {
		t.Fatalf("at per-IP ceiling: %d", g)
	}
	s.RefundAnonRows("192.0.2.1", 25, 30)
	if g := s.ReserveAnonRows("192.0.2.2", 100, 1000, 30); g != 25 {
		t.Fatalf("global ceiling after refund: %d", g)
	}
	if g := s.ReserveAnonRows("192.0.2.3", 5, 0, 0); g != 5 {
		t.Fatalf("no anon ceiling: %d", g)
	}
}

func TestParseTier(t *testing.T) {
	for in, want := range map[string]Tier{"demo": TierDemo, "Standard": TierStandard, "batch": TierBatch, " anonymous ": TierAnonymous} {
		if got, err := ParseTier(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"standrad", "", "gold"} {
		if _, err := ParseTier(in); !errors.Is(err, ErrUnknownTier) {
			t.Errorf("%q: want ErrUnknownTier, got %v", in, err)
		}
	}
}
