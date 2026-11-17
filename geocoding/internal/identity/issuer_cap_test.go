package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestJWTIssuerCapPerOrg(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "o@acme.example", "")
	org, _ := s.CreateOrg(ctx, "Acme", "acme", u.ID, false, false)
	org2, _ := s.CreateOrg(ctx, "Other", "other", u.ID, false, false)
	mk := func(orgID int64, i int) JWTIssuer {
		return JWTIssuer{OrgID: orgID, Issuer: fmt.Sprintf("https://idp%d.example", i), Audience: "aud", Enabled: true}
	}
	var last JWTIssuer
	for i := 0; i < MaxJWTIssuersPerOrg; i++ {
		j, err := s.SaveJWTIssuer(ctx, mk(org.ID, i))
		if err != nil {
			t.Fatalf("issuer %d: %v", i, err)
		}
		last = j
	}
	if _, err := s.SaveJWTIssuer(ctx, mk(org.ID, 99)); !errors.Is(err, ErrTooManyIssuers) {
		t.Fatalf("over cap: %v", err)
	}
	// Updates at the cap still work, and other orgs are unaffected.
	last.Audience = "aud2"
	if _, err := s.SaveJWTIssuer(ctx, last); err != nil {
		t.Fatalf("update at cap: %v", err)
	}
	if _, err := s.SaveJWTIssuer(ctx, mk(org2.ID, 50)); err != nil {
		t.Fatalf("other org: %v", err)
	}
	// A duplicate is still a conflict, not a cap error, below the cap.
	if _, err := s.SaveJWTIssuer(ctx, mk(org2.ID, 50)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
}
