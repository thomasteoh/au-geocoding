package apiauth

import (
	"context"
	"errors"
	"testing"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
)

// An (issuer, audience) pair is unique per org, not globally: a second org
// can register the pair the first org uses (so nobody can squat it first),
// and a token for a pair two orgs hold is refused as ambiguous rather than
// credited to either.
func TestBearerSharedIssuerAudienceRefused(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	tok := "Bearer " + f.idp.Sign(f.claims())
	if _, err := f.call(t, map[string]string{"Authorization": tok}); err != nil {
		t.Fatalf("before: %v (%v)", err, f.reasons)
	}
	u, _ := f.ids.CreateUser(ctx, "x@other.example", "")
	org2, _ := f.ids.CreateOrg(ctx, "Other", "other", u.ID, false, false)
	reg, err := f.ids.SaveJWTIssuer(ctx, identity.JWTIssuer{OrgID: org2.ID, Issuer: f.idp.Issuer, Audience: "https://geo.example/api", Enabled: true})
	if err != nil {
		t.Fatalf("second org could not register the same pair: %v", err)
	}
	if _, err := f.ids.SaveJWTIssuer(ctx, identity.JWTIssuer{OrgID: org2.ID, Issuer: f.idp.Issuer, Audience: "https://geo.example/api", Enabled: true}); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("same org registered the pair twice: %v", err)
	}
	f.reasons = nil
	if _, err := f.call(t, map[string]string{"Authorization": tok}); !errors.Is(err, publicapi.ErrInvalidKey) {
		t.Fatalf("ambiguous registration accepted: %v", err)
	}
	if len(f.reasons) != 1 || f.reasons[0] != "audience" {
		t.Fatalf("reason: %v", f.reasons)
	}
	for _, org := range []int64{f.org.ID, org2.ID} {
		if shared, _ := f.ids.SharedJWTIssuers(ctx, org); len(shared) != 1 {
			t.Fatalf("org %d not warned: %v", org, shared)
		}
	}
	// Once the squatter removes it, the owner's tokens work again.
	f.ids.DeleteJWTIssuer(ctx, org2.ID, reg.ID)
	if _, err := f.call(t, map[string]string{"Authorization": tok}); err != nil {
		t.Fatalf("after removal: %v (%v)", err, f.reasons)
	}
}
