package apiauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"augeocoding/internal/appdb"
	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
	"augeocoding/internal/safehttp"
)

type fixture struct {
	auth    *Authenticator
	idp     *authtest.IdP
	ids     *identity.Store
	keys    *publicapi.Store
	org     identity.Org
	reasons []string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db, err := appdb.Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, err := publicapi.New(db)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := identity.New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u, _ := ids.CreateUser(ctx, "o@acme.example", "")
	org, _ := ids.CreateOrg(ctx, "Acme", "acme", u.ID, false, false)
	ids.SetOrgTier(ctx, org.ID, "standard")
	org, _ = ids.OrgByID(ctx, org.ID)
	idp := authtest.NewIdP(t)
	if _, err := ids.SaveJWTIssuer(ctx, identity.JWTIssuer{OrgID: org.ID, Issuer: idp.Issuer, Audience: "https://geo.example/api", ScopePrefix: "geo:", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	f := &fixture{idp: idp, ids: ids, keys: keys, org: org}
	f.auth = &Authenticator{
		Keys: keys, Issuers: ids,
		KeyLimiter: publicapi.NewRateLimiter(100, 100), AnonLimiter: publicapi.NewRateLimiter(100, 100),
		ClientIP:   func(r *http.Request) string { return "192.0.2.1" },
		Reject:     func(r string) { f.reasons = append(f.reasons, r) },
		HTTPClient: safehttp.Client(5*time.Second, true),
	}
	return f
}

func (f *fixture) claims() map[string]any {
	now := time.Now()
	return map[string]any{"iss": f.idp.Issuer, "sub": "svc-1", "aud": "https://geo.example/api", "exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(), "scope": "geo:search openid"}
}

func (f *fixture) call(t *testing.T, headers map[string]string) (publicapi.Principal, error) {
	t.Helper()
	r := httptest.NewRequest("POST", "/search", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return f.auth.Authenticate(r)
}

func TestBearerAccepted(t *testing.T) {
	f := setup(t)
	p, err := f.call(t, map[string]string{"Authorization": "Bearer " + f.idp.Sign(f.claims())})
	if err != nil {
		t.Fatalf("valid token: %v (%v)", err, f.reasons)
	}
	if p.Kind != "jwt" || p.OrgID != f.org.ID || p.Tier != publicapi.TierStandard || p.UsageKey != publicapi.OrgUsageKey(f.org.ID) {
		t.Fatalf("principal: %+v", p)
	}
	if len(p.Scopes) != 1 || p.Scopes[0] != "search" {
		t.Fatalf("scopes: %v", p.Scopes)
	}
}

func TestBearerRejections(t *testing.T) {
	f := setup(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]func() string{
		"expired": func() string {
			c := f.claims()
			c["exp"] = time.Now().Add(-5 * time.Minute).Unix()
			return f.idp.Sign(c)
		},
		"no exp": func() string {
			c := f.claims()
			delete(c, "exp")
			return f.idp.Sign(c)
		},
		"not yet valid": func() string {
			c := f.claims()
			c["nbf"] = time.Now().Add(10 * time.Minute).Unix()
			return f.idp.Sign(c)
		},
		"wrong audience": func() string {
			c := f.claims()
			c["aud"] = "someone-else"
			return f.idp.Sign(c)
		},
		"unknown issuer": func() string {
			c := f.claims()
			c["iss"] = "https://evil.example"
			return f.idp.Sign(c)
		},
		"forged signature": func() string { return authtest.SignWith(other, f.idp.KeyID, f.claims()) },
		"hs256 confusion":  func() string { return authtest.HS256([]byte("secret-secret-secret-secret-1234"), f.claims()) },
		"no api scope": func() string {
			c := f.claims()
			c["scope"] = "openid search" // unprefixed
			return f.idp.Sign(c)
		},
		"garbage": func() string { return "not.a.jwt" },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.call(t, map[string]string{"Authorization": "Bearer " + mk()})
			if !errors.Is(err, publicapi.ErrInvalidKey) {
				t.Fatalf("got %v, want uniform ErrInvalidKey", err)
			}
		})
	}
}

func TestBearerAudienceSelectsOrgKeys(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// A second org registers the same issuer with its own audience and a
	// JWKS URL it controls. Tokens for the first org's audience must still
	// be verified with the first org's keys only.
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	evil := authtest.NewIdP(t)
	evil.Key, evil.KeyID = attacker, "k1"
	u, _ := f.ids.CreateUser(ctx, "x@evil.example", "")
	org2, _ := f.ids.CreateOrg(ctx, "Evil", "evil", u.ID, false, false)
	if _, err := f.ids.SaveJWTIssuer(ctx, identity.JWTIssuer{OrgID: org2.ID, Issuer: f.idp.Issuer, Audience: "evil-aud", JWKSURL: evil.Issuer + "/jwks", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	forged := authtest.SignWith(attacker, "k1", f.claims()) // aimed at org 1's audience
	if _, err := f.call(t, map[string]string{"Authorization": "Bearer " + forged}); !errors.Is(err, publicapi.ErrInvalidKey) {
		t.Fatalf("token signed by org 2's JWKS accepted for org 1: %v", err)
	}
	// Two audiences in one token is ambiguous and refused.
	c := f.claims()
	c["aud"] = []string{"https://geo.example/api", "evil-aud"}
	if _, err := f.call(t, map[string]string{"Authorization": "Bearer " + f.idp.Sign(c)}); !errors.Is(err, publicapi.ErrInvalidKey) {
		t.Fatalf("ambiguous audience accepted: %v", err)
	}
}

func TestBearerSubjectAllowlist(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	regs, _ := f.ids.JWTIssuers(ctx, f.org.ID)
	regs[0].AllowedSubjects = []string{"svc-2"}
	if _, err := f.ids.SaveJWTIssuer(ctx, regs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.call(t, map[string]string{"Authorization": "Bearer " + f.idp.Sign(f.claims())}); !errors.Is(err, publicapi.ErrInvalidKey) {
		t.Fatal("subject outside allowlist accepted")
	}
	c := f.claims()
	c["sub"] = "svc-2"
	if _, err := f.call(t, map[string]string{"Authorization": "Bearer " + f.idp.Sign(c)}); err != nil {
		t.Fatalf("allowed subject: %v", err)
	}
}

func TestBothCredentialsAndAnonymous(t *testing.T) {
	f := setup(t)
	if _, err := f.call(t, map[string]string{"X-Api-Key": "x", "Authorization": "Bearer y"}); !errors.Is(err, ErrBothCredentials) {
		t.Fatalf("both: %v", err)
	}
	p, err := f.call(t, nil)
	if err != nil || !p.Anonymous() || p.RateKey != "anon:192.0.2.1" {
		t.Fatalf("anonymous: %+v %v", p, err)
	}
	if _, err := f.call(t, map[string]string{"X-Api-Key": "nope"}); !errors.Is(err, publicapi.ErrInvalidKey) {
		t.Fatalf("bad key: %v", err)
	}
	_, raw, _ := f.keys.IssueKeyWith(publicapi.IssueOptions{Label: "k", Tier: publicapi.TierDemo, OrgID: f.org.ID})
	p, err = f.call(t, map[string]string{"X-Api-Key": raw})
	if err != nil || p.Kind != "key" || p.UsageKey != publicapi.OrgUsageKey(f.org.ID) {
		t.Fatalf("org key: %+v %v", p, err)
	}
}

func TestBearerDisabledWithoutIssuers(t *testing.T) {
	f := setup(t)
	f.auth.Issuers = nil
	if _, err := f.call(t, map[string]string{"Authorization": "Bearer " + f.idp.Sign(f.claims())}); !errors.Is(err, publicapi.ErrInvalidKey) {
		t.Fatalf("bearer with no issuer source: %v", err)
	}
}

func TestMapScopes(t *testing.T) {
	for _, tc := range []struct {
		scope  string
		scp    string
		roles  []string
		prefix string
		want   []string
	}{
		{"search batch", "", nil, "", []string{"search", "batch"}},
		{"", `["api.search"]`, nil, "api.", []string{"search"}},
		{"", `"geo.search geo.batch"`, nil, "geo.", []string{"search", "batch"}}, // Entra delegated scp string
		{"", "", []string{"Geo.Batch"}, "Geo.", []string{"batch"}},               // Entra app roles
		{"openid profile", "", nil, "", nil},
		{"search", "", nil, "geo:", nil},
	} {
		got := MapScopes(tc.scope, json.RawMessage(tc.scp), tc.roles, tc.prefix)
		if len(got) != len(tc.want) {
			t.Fatalf("MapScopes(%q,%q,%v,%q) = %v, want %v", tc.scope, tc.scp, tc.roles, tc.prefix, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("MapScopes = %v, want %v", got, tc.want)
			}
		}
	}
}
