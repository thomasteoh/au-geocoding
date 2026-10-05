package oidcrp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
)

var ctx = context.Background()

func setup(t *testing.T) (*RP, *authtest.IdP, identity.Connection) {
	idp := authtest.NewIdP(t)
	rp := &RP{CallbackURL: "https://geo.example/auth/oidc/callback", HTTP: idp.Server.Client()}
	c := identity.Connection{ID: 1, Slug: "okta", Kind: identity.KindOIDC, Preset: "okta", Enabled: true,
		Issuer: idp.Issuer, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret}
	return rp, idp, c
}

// authorize runs the browser leg: follow the auth URL to the IdP and return
// the callback query it redirects to.
func authorize(t *testing.T, rp *RP, c identity.Connection, f identity.Flow, state string) url.Values {
	t.Helper()
	u, err := rp.AuthURL(ctx, c, state, f.Nonce, f.PKCEVerifier)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(loc.String(), rp.CallbackURL) {
		t.Fatalf("redirected to %s", loc)
	}
	if loc.Query().Get("state") != state {
		t.Fatal("state not echoed")
	}
	return loc.Query()
}

func flow() identity.Flow {
	return identity.Flow{Kind: "oidc", Nonce: identity.RandomToken(16), PKCEVerifier: identity.RandomToken(32)}
}

func TestOIDCLogin(t *testing.T) {
	rp, idp, c := setup(t)
	idp.SetUser(authtest.User{Subject: "u1", Email: "Dev@Acme.example", EmailVerified: true, Name: "Dev", Groups: []string{"geo-admins"}, SID: "s1"})
	f := flow()
	q := authorize(t, rp, c, f, "st")
	a, err := rp.Callback(ctx, c, f, q)
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != "u1" || a.Email != "Dev@Acme.example" || !a.EmailTrusted || a.IdPSID != "s1" || len(a.Groups) != 1 || a.IDToken == "" {
		t.Fatalf("assertion: %+v", a)
	}
}

func TestOIDCUnverifiedEmailNotTrusted(t *testing.T) {
	rp, idp, c := setup(t)
	idp.SetUser(authtest.User{Subject: "u1", Email: "x@acme.example", EmailVerified: false})
	f := flow()
	a, err := rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st"))
	if err != nil || a.EmailTrusted {
		t.Fatalf("unverified email trusted: %+v %v", a, err)
	}
	// Entra never trusts email without xms_edov, even when "verified".
	c.Preset = "entra"
	idp.SetUser(authtest.User{Subject: "u2", Email: "x@acme.example", EmailVerified: true})
	f = flow()
	a, err = rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st"))
	if err != nil || a.EmailTrusted {
		t.Fatalf("entra email trusted without xms_edov: %+v %v", a, err)
	}
	idp.Tamper = func(m map[string]any) { m["xms_edov"] = true }
	f = flow()
	a, err = rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st"))
	if err != nil || !a.EmailTrusted {
		t.Fatalf("entra with xms_edov: %+v %v", a, err)
	}
}

func TestOIDCRejectsNonceMismatch(t *testing.T) {
	rp, idp, c := setup(t)
	idp.SetUser(authtest.User{Subject: "u1", Email: "a@b.example", EmailVerified: true})
	f := flow()
	q := authorize(t, rp, c, f, "st")
	f.Nonce = "other"
	if _, err := rp.Callback(ctx, c, f, q); !errors.Is(err, ErrToken) {
		t.Fatalf("nonce mismatch: %v", err)
	}
}

func TestOIDCRejectsWrongPKCEVerifier(t *testing.T) {
	rp, idp, c := setup(t)
	idp.SetUser(authtest.User{Subject: "u1"})
	f := flow()
	q := authorize(t, rp, c, f, "st")
	f.PKCEVerifier = identity.RandomToken(32)
	if _, err := rp.Callback(ctx, c, f, q); !errors.Is(err, ErrToken) {
		t.Fatalf("wrong verifier: %v", err)
	}
}

func TestOIDCMixUpDefence(t *testing.T) {
	rp, idp, c := setup(t)
	idp.SetUser(authtest.User{Subject: "u1"})
	idp.IssParamOverride = "https://attacker.example"
	f := flow()
	if _, err := rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st")); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("iss mismatch: %v", err)
	}
}

func TestOIDCRejectsTamperedAudience(t *testing.T) {
	rp, idp, c := setup(t)
	idp.SetUser(authtest.User{Subject: "u1"})
	idp.Tamper = func(m map[string]any) { m["aud"] = "another-client" }
	f := flow()
	if _, err := rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st")); !errors.Is(err, ErrToken) {
		t.Fatalf("wrong aud: %v", err)
	}
}

func TestOIDCErrorFromIdP(t *testing.T) {
	rp, _, c := setup(t)
	if _, err := rp.Callback(ctx, c, flow(), url.Values{"error": {"access_denied"}}); !errors.Is(err, ErrIdP) {
		t.Fatalf("idp error: %v", err)
	}
}

func TestEndSessionURL(t *testing.T) {
	rp, _, c := setup(t)
	u, ok := rp.EndSessionURL(ctx, c, "tok", "https://geo.example/auth/login")
	if !ok || !strings.Contains(u, "/logout?") || !strings.Contains(u, "id_token_hint=tok") || !strings.Contains(u, "post_logout_redirect_uri=") {
		t.Fatalf("end session: %q %v", u, ok)
	}
}

func logoutClaims(idp *authtest.IdP) map[string]any {
	return map[string]any{"iss": idp.Issuer, "aud": idp.ClientID, "iat": time.Now().Unix(), "jti": identity.RandomToken(8), "sid": "s1",
		"events": map[string]any{backchannelEvent: map[string]any{}}}
}

func TestLogoutToken(t *testing.T) {
	rp, idp, c := setup(t)
	lt, err := rp.VerifyLogoutToken(ctx, c, idp.Sign(logoutClaims(idp)))
	if err != nil || lt.SID != "s1" || lt.JTI == "" {
		t.Fatalf("valid logout token: %+v %v", lt, err)
	}
	bad := map[string]func(map[string]any){
		"nonce":     func(m map[string]any) { m["nonce"] = "n" },
		"no event":  func(m map[string]any) { delete(m, "events") },
		"no jti":    func(m map[string]any) { delete(m, "jti") },
		"no sid":    func(m map[string]any) { delete(m, "sid") },
		"stale iat": func(m map[string]any) { m["iat"] = time.Now().Add(-time.Hour).Unix() },
		"wrong aud": func(m map[string]any) { m["aud"] = "x" },
		"wrong iss": func(m map[string]any) { m["iss"] = "https://evil.example" },
	}
	for name, edit := range bad {
		m := logoutClaims(idp)
		edit(m)
		if _, err := rp.VerifyLogoutToken(ctx, c, idp.Sign(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGitHubLogin(t *testing.T) {
	var gotVerifier string
	mux := http.NewServeMux()
	gh := httptest.NewServer(mux)
	defer gh.Close()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotVerifier = r.PostForm.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "gho_x", "token_type": "bearer"})
	})
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octo", "email": "public@unverified.example"})
	})
	mux.HandleFunc("/api/user/emails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{{"email": "other@x.example", "primary": false, "verified": true}, {"email": "octo@x.example", "primary": true, "verified": true}})
	})
	mux.HandleFunc("/api/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{{"login": "acme"}})
	})
	rp := &RP{CallbackURL: "https://geo.example/auth/oidc/callback", HTTP: gh.Client(),
		GitHub: GitHubEndpoints{AuthURL: gh.URL + "/authorize", TokenURL: gh.URL + "/token", APIURL: gh.URL + "/api"}}
	c := identity.Connection{ID: 2, Slug: "github", Kind: identity.KindGitHub, Enabled: true, ClientID: "id", ClientSecret: "s"}
	f := flow()
	u, _ := rp.AuthURL(ctx, c, "st", "", f.PKCEVerifier)
	if !strings.Contains(u, "code_challenge_method=S256") {
		t.Fatalf("no PKCE in %s", u)
	}
	a, err := rp.Callback(ctx, c, f, url.Values{"code": {"c"}, "state": {"st"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != "42" || a.Email != "octo@x.example" || !a.EmailTrusted || gotVerifier != f.PKCEVerifier {
		t.Fatalf("github assertion: %+v verifier=%q", a, gotVerifier)
	}
	c.AllowedOrgs = []string{"other-org"}
	_, err = rp.Callback(ctx, c, f, url.Values{"code": {"c"}})
	var d *identity.Denial
	if !errors.As(err, &d) || d.Code != "github_org" {
		t.Fatalf("org restriction: %v", err)
	}
}

func TestEntraTenantAllowlist(t *testing.T) {
	rp, idp, c := setup(t)
	c.Preset = "entra"
	c.AllowedTenants = []string{"11111111-1111-1111-1111-111111111111"}
	idp.SetUser(authtest.User{Subject: "u1", Email: "a@b.example"})
	idp.Tamper = func(m map[string]any) { m["tid"] = "22222222-2222-2222-2222-222222222222" }
	f := flow()
	_, err := rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st"))
	var d *identity.Denial
	if !errors.As(err, &d) || d.Code != "tenant_not_allowed" {
		t.Fatalf("foreign tenant: %v", err)
	}
	idp.Tamper = func(m map[string]any) { m["tid"] = "11111111-1111-1111-1111-111111111111" }
	f = flow()
	if _, err := rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st")); err != nil {
		t.Fatalf("allowed tenant: %v", err)
	}
}

func TestEntraGroupOverage(t *testing.T) {
	rp, idp, c := setup(t)
	c.Preset = "entra"
	status := http.StatusOK
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me/getMemberGroups" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"value": []string{"g-1", "g-2"}})
	}))
	defer graph.Close()
	rp.GraphURL = graph.URL
	idp.SetUser(authtest.User{Subject: "u1"})
	idp.Tamper = func(m map[string]any) {
		m["_claim_names"] = map[string]any{"groups": "src1"}
		m["_claim_sources"] = map[string]any{"src1": map[string]any{"endpoint": "https://graph.windows.net/x/users/y/getMemberObjects"}}
	}
	f := flow()
	a, err := rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st"))
	if err != nil || len(a.Groups) != 2 || a.GroupsUnknown {
		t.Fatalf("overage via graph: %+v %v", a, err)
	}
	status = http.StatusForbidden
	f = flow()
	a, err = rp.Callback(ctx, c, f, authorize(t, rp, c, f, "st"))
	if err != nil || !a.GroupsUnknown {
		t.Fatalf("graph failure should mark groups unknown: %+v %v", a, err)
	}
}
