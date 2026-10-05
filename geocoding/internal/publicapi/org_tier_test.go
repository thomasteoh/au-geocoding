package publicapi

import (
	"context"
	"testing"
)

func TestSetOrgTierTx(t *testing.T) {
	s, err := Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	k, raw, err := s.IssueKeyWith(IssueOptions{Label: "a", Tier: TierDemo, OrgID: 7})
	if err != nil {
		t.Fatal(err)
	}

	// Rolled back: neither the table nor the index changes.
	tx, _ := s.db.BeginTx(ctx, nil)
	if err := s.SetOrgTierTx(ctx, tx, 7, TierBatch); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	if got, _ := s.OrgKey(7, k.ID); got.Tier != TierDemo {
		t.Fatalf("table after rollback: %v", got.Tier)
	}
	if a, _ := s.Authenticate(raw); a.Tier != TierDemo {
		t.Fatalf("index after rollback: %v", a.Tier)
	}

	// Committed, then applied.
	tx, _ = s.db.BeginTx(ctx, nil)
	if err := s.SetOrgTierTx(ctx, tx, 7, TierBatch); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s.ApplyOrgTier(7, TierBatch)
	if got, _ := s.OrgKey(7, k.ID); got.Tier != TierBatch {
		t.Fatalf("table after commit: %v", got.Tier)
	}
	if a, _ := s.Authenticate(raw); a.Tier != TierBatch {
		t.Fatalf("index after apply: %v", a.Tier)
	}
}
