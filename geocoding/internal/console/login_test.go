package console

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
)

var open = identity.LoginPolicy{SignupOpen: true}

func TestOIDCLoginEndToEnd(t *testing.T) {
	h := newHarness(t, open)
	b := h.browser()
	r := b.login(authtest.User{Subject: "s1", Email: "ada@example.com", EmailVerified: true, Name: "Ada", SID: "sid-1"})
	if r.Status != http.StatusSeeOther || r.Location != "/console" {
		t.Fatalf("callback: %d %s %s", r.Status, r.Location, r.Body)
	}
	// One personal org → home redirects into it.
	r = b.get("/console")
	if r.Status != http.StatusSeeOther || !strings.HasPrefix(r.Location, "/console/orgs/") {
		t.Fatalf("home: %d %s", r.Status, r.Location)
	}
	r = b.get(r.Location)
	if r.Status != http.StatusOK || !strings.Contains(r.Body, "Rows today") {
		t.Fatalf("overview: %d", r.Status)
	}
	events, _ := h.ids.AuditLog(h.ctx, 0, 0, 10)
	if len(events) == 0 || events[0].Action != "login.success" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	h := newHarness(t, open)
	b := h.browser()
	h.idp.SetUser(authtest.User{Subject: "s1", Email: "a@example.com", EmailVerified: true})
	r := b.get("/auth/oidc/test-idp/start")
	r = b.get(r.Location)
	req, _ := http.NewRequest(http.MethodGet, r.Location, nil)
	res, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var sess *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			sess = c
		}
	}
	if sess == nil || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode || sess.Path != "/" || sess.Domain != "" {
		t.Fatalf("session cookie: %+v", sess)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("csp: %q", csp)
	}
	if res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("referrer policy missing")
	}
}

func TestFlowBoundToBrowser(t *testing.T) {
	h := newHarness(t, open)
	victim, attacker := h.browser(), h.browser()
	// The attacker starts a login and lures the victim to the callback.
	h.idp.SetUser(authtest.User{Subject: "attacker", Email: "mallory@example.com", EmailVerified: true})
	r := attacker.get("/auth/oidc/test-idp/start")
	r = attacker.get(r.Location)
	r = victim.get(r.Location)
	if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "expired or was started in another browser") {
		t.Fatalf("cross-browser callback: %d %s", r.Status, r.Location)
	}
	if victim.get("/console").Status != http.StatusSeeOther {
		t.Fatal("victim got a session")
	}
}

func TestReturnToRestricted(t *testing.T) {
	for in, want := range map[string]string{
		"/console/orgs/x/keys": "/console/orgs/x/keys", "https://evil.example": "/console", "//evil.example": "/console",
		"/consolex": "/consolex", "/auth/logout": "/console", "/console\\@evil": "/console", "": "/console",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
	h := newHarness(t, open)
	b := h.browser()
	h.idp.SetUser(authtest.User{Subject: "s", Email: "r@example.com", EmailVerified: true})
	r := b.get("/auth/oidc/test-idp/start?return_to=" + url.QueryEscape("https://evil.example/"))
	r = b.get(r.Location)
	r = b.get(r.Location)
	if r.Location != "/console" {
		t.Fatalf("open redirect: %s", r.Location)
	}
}

func TestCSRFAndOriginRequired(t *testing.T) {
	h := newHarness(t, open)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "c@example.com", EmailVerified: true})
	// No token.
	if r := b.post("/auth/logout", nil, false); r.Status != http.StatusForbidden {
		t.Fatalf("logout without csrf: %d", r.Status)
	}
	// Token but cross-site origin.
	tok := b.csrf()
	b.origin = "https://evil.example"
	if r := b.post("/auth/logout", url.Values{"csrf": {tok}}, false); r.Status != http.StatusForbidden {
		t.Fatalf("logout cross-origin: %d", r.Status)
	}
	b.origin = h.srv.URL
	if r := b.post("/auth/logout", nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("logout: %d %s", r.Status, r.Body)
	}
	if r := b.get("/console/account"); r.Status != http.StatusSeeOther || !strings.HasPrefix(r.Location, "/auth/login") {
		t.Fatalf("after logout: %d %s", r.Status, r.Location)
	}
}

func TestLogoutRedirectsToEndSession(t *testing.T) {
	h := newHarness(t, open)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "e@example.com", EmailVerified: true})
	r := b.post("/auth/logout", nil, true)
	if r.Status != http.StatusSeeOther || !strings.HasPrefix(r.Location, h.idp.Issuer+"/logout?") || !strings.Contains(r.Location, "id_token_hint=") {
		t.Fatalf("rp-initiated logout: %d %s", r.Status, r.Location)
	}
}

func TestBackchannelLogoutEndsSession(t *testing.T) {
	h := newHarness(t, open)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "bc@example.com", EmailVerified: true, SID: "idp-session-1"})
	tok := h.idp.Sign(map[string]any{"iss": h.idp.Issuer, "aud": h.idp.ClientID, "iat": time.Now().Unix(), "jti": "j1", "sid": "idp-session-1",
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}})
	post := func() int {
		res, err := h.srv.Client().PostForm(h.srv.URL+"/auth/oidc/test-idp/backchannel-logout", url.Values{"logout_token": {tok}})
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if s := post(); s != http.StatusOK {
		t.Fatalf("backchannel: %d", s)
	}
	if r := b.get("/console/account"); r.Status != http.StatusSeeOther {
		t.Fatalf("session survived back-channel logout: %d", r.Status)
	}
	if s := post(); s != http.StatusBadRequest {
		t.Fatalf("replayed logout token: %d", s)
	}
}

func TestOrgPagesHiddenFromNonMembers(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	h.org("acme", owner)
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "s1", Email: "outsider@example.com", EmailVerified: true})
	if r := b.get("/console/orgs/acme"); r.Status != http.StatusNotFound {
		t.Fatalf("non-member: %d", r.Status)
	}
	if r := b.get("/console/orgs/does-not-exist"); r.Status != http.StatusNotFound {
		t.Fatalf("missing org: %d", r.Status)
	}
	if r := b.get("/console/admin"); r.Status != http.StatusNotFound {
		t.Fatalf("admin for non-admin: %d", r.Status)
	}
}

func TestDiscoveryAndSSOEnforcement(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	d, _ := h.ids.AddDomain(h.ctx, org.ID, "acme.example")
	h.ids.MarkDomainVerified(h.ctx, org.ID, d.ID)
	h.ids.UpdateOrgSettings(h.ctx, org.ID, identity.OrgSettings{Name: "Acme", SSOEnforced: true, JITEnabled: true, DefaultRole: identity.RoleViewer})
	h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: org.ID, Slug: "acme-okta", Kind: identity.KindOIDC, Preset: "okta", Name: "Acme Okta",
		Enabled: true, Issuer: "https://acme.okta.example", ClientID: "x"})
	b := h.browser()
	r := b.post("/auth/discover", url.Values{"email": {"dev@acme.example"}}, false)
	if r.Status != http.StatusSeeOther || r.Location != "/auth/oidc/acme-okta/start" {
		t.Fatalf("discover: %d %s", r.Status, r.Location)
	}
	// Platform IdP login for an enforced domain is refused with a pointer.
	r = b.login(authtest.User{Subject: "s9", Email: "dev@acme.example", EmailVerified: true})
	if r.Status != http.StatusForbidden || !strings.Contains(r.Body, "single sign-on") || !strings.Contains(r.Body, "acme-okta") {
		t.Fatalf("enforced: %d %s", r.Status, r.Body)
	}
}
