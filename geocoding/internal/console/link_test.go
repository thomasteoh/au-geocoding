package console

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
)

// orgSSO sets up acme with a verified domain, enforced SSO and an org OIDC
// connection backed by a second fake IdP.
func (h *harness) orgSSO(t *testing.T) (identity.Org, *authtest.IdP, identity.Connection) {
	t.Helper()
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	d, _ := h.ids.AddDomain(h.ctx, org.ID, "acme.example")
	h.ids.MarkDomainVerified(h.ctx, org.ID, d.ID)
	h.ids.UpdateOrgSettings(h.ctx, org.ID, identity.OrgSettings{Name: "Acme", SSOEnforced: true, DefaultRole: identity.RoleViewer})
	idp2 := authtest.NewIdP(t)
	c, err := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: org.ID, Slug: "acme-sso", Kind: identity.KindOIDC, Preset: "okta", Name: "Acme SSO",
		Enabled: true, Issuer: idp2.Issuer, ClientID: idp2.ClientID, ClientSecret: idp2.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}
	org, _ = h.ids.OrgByID(h.ctx, org.ID)
	return org, idp2, c
}

// follow walks a redirect chain through the IdP back to the console.
func (b *browser) follow(r resp, hops int) resp {
	b.h.t.Helper()
	for i := 0; i < hops && r.Location != "" && (r.Status == http.StatusFound || r.Status == http.StatusSeeOther); i++ {
		r = b.get(r.Location)
	}
	return r
}

func TestLinkAndPerOrgSSOEnforcement(t *testing.T) {
	h := newHarness(t, open)
	org, idp2, _ := h.orgSSO(t)
	// A guest member at another domain signs in through the platform IdP.
	guest := h.browser()
	guest.mustLogin(authtest.User{Subject: "g1", Email: "guest@personal.example", EmailVerified: true})
	u, _ := h.ids.UserByEmail(h.ctx, "guest@personal.example")
	h.ids.SetMembership(h.ctx, org.ID, u.ID, identity.RoleDeveloper, "manual")

	// Enforcement: the platform session does not reach acme's pages.
	r := guest.get("/console/orgs/acme/keys")
	if r.Status != http.StatusForbidden || !strings.Contains(r.Body, "Single sign-on required") || !strings.Contains(r.Body, "/auth/oidc/acme-sso/start") {
		t.Fatalf("enforced org via platform session: %d", r.Status)
	}
	if r := guest.post("/console/orgs/acme/keys", nil, true); r.Status != http.StatusForbidden {
		t.Fatalf("enforced POST: %d", r.Status)
	}
	// Other orgs are unaffected.
	if r := guest.get("/console?all=1"); r.Status != http.StatusOK {
		t.Fatalf("home: %d", r.Status)
	}

	// Link the person's acme IdP account explicitly.
	idp2.SetUser(authtest.User{Subject: "acme-guest", Email: "guest@acme.example"})
	r = guest.post("/console/account/links/acme-sso", nil, true)
	if r.Status != http.StatusSeeOther || !strings.HasPrefix(r.Location, idp2.Issuer) {
		t.Fatalf("link start: %d %s", r.Status, r.Location)
	}
	r = guest.follow(r, 2)
	if r.Location != "/console/account" {
		t.Fatalf("link finish: %d %s %s", r.Status, r.Location, r.Body)
	}
	if page := guest.get("/console/account"); !strings.Contains(page.Body, "Linked Acme SSO") || !strings.Contains(page.Body, "guest@acme.example") {
		t.Fatal("link not shown on account page")
	}
	// Still a platform session: acme stays closed until an acme sign-in.
	if r := guest.get("/console/orgs/acme/keys"); r.Status != http.StatusForbidden {
		t.Fatalf("enforcement after link: %d", r.Status)
	}
	r = guest.follow(guest.get("/auth/oidc/acme-sso/start?return_to=/console/orgs/acme/keys"), 3)
	if r.Status != http.StatusOK || !strings.Contains(r.Body, "API keys") {
		t.Fatalf("after acme SSO: %d %s", r.Status, r.Location)
	}
	// The acme sign-in is the same account.
	if events, _ := h.ids.AuditLog(h.ctx, org.ID, 0, 20); len(events) == 0 {
		t.Fatal("no org audit events")
	}
	ids, _ := h.ids.LinkedIdentities(h.ctx, u.ID)
	if len(ids) != 2 {
		t.Fatalf("identities: %+v", ids)
	}
}

func TestLinkRules(t *testing.T) {
	h := newHarness(t, open)
	_, idp2, _ := h.orgSSO(t)
	a, b := h.browser(), h.browser()
	a.mustLogin(authtest.User{Subject: "a1", Email: "a@personal.example", EmailVerified: true})
	b.mustLogin(authtest.User{Subject: "b1", Email: "b@personal.example", EmailVerified: true})
	ua, _ := h.ids.UserByEmail(h.ctx, "a@personal.example")
	org, _ := h.ids.OrgBySlug(h.ctx, "acme")
	h.ids.SetMembership(h.ctx, org.ID, ua.ID, identity.RoleViewer, "manual")

	// Only connections the person can use are linkable.
	if r := b.post("/console/account/links/acme-sso", nil, true); !strings.Contains(b.flash(r), "not available to link") {
		t.Fatal("non-member linked an org connection")
	}
	// An identity linked to one account cannot be linked to another.
	idp2.SetUser(authtest.User{Subject: "shared", Email: "x@acme.example"})
	a.follow(a.post("/console/account/links/acme-sso", nil, true), 2)
	h.ids.SetMembership(h.ctx, org.ID, mustUserID(t, h, "b@personal.example"), identity.RoleViewer, "manual")
	r := b.follow(b.post("/console/account/links/acme-sso", nil, true), 2)
	if r.Location != "/console/account" || !strings.Contains(b.flash(r), "already linked to another account") {
		t.Fatalf("steal identity: %d %s", r.Status, r.Location)
	}
	// A stale session cannot link.
	old := passkeyNow
	passkeyNow = func() time.Time { return time.Now().Add(time.Hour) }
	defer func() { passkeyNow = old }()
	if r := a.post("/console/account/links/test-idp", nil, true); !strings.Contains(a.flash(r), "Sign in again") {
		t.Fatal("stale session linked")
	}
	passkeyNow = old
	// Unlink works but never removes the last method.
	ids, _ := h.ids.LinkedIdentities(h.ctx, ua.ID)
	if len(ids) != 2 {
		t.Fatalf("identities: %+v", ids)
	}
	for _, id := range ids {
		if id.Connection.Slug == "acme-sso" {
			a.post("/console/account/identities/"+itoa(id.ID)+"/unlink", nil, true)
		}
	}
	ids, _ = h.ids.LinkedIdentities(h.ctx, ua.ID)
	if len(ids) != 1 {
		t.Fatalf("after unlink: %+v", ids)
	}
	if r := a.post("/console/account/identities/"+itoa(ids[0].ID)+"/unlink", nil, true); !strings.Contains(a.flash(r), "only way to sign in") {
		t.Fatal("removed last method")
	}
}

func mustUserID(t *testing.T, h *harness, email string) int64 {
	t.Helper()
	u, err := h.ids.UserByEmail(h.ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestSSOSatisfiedRules(t *testing.T) {
	h := newHarness(t, open)
	org, _, c := h.orgSSO(t)
	u := h.user("dev@acme.example")
	oc := &OrgContext{Org: org, Role: identity.RoleDeveloper}
	r, _ := http.NewRequest("GET", "/", nil)
	sess := func(method string, conn int64) identity.Session {
		_, x, err := h.ids.CreateSession(h.ctx, identity.NewSession{UserID: u.ID, Method: method, ConnectionID: conn}, h.con.Cfg.Session)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	v := &Viewer{User: u, Session: sess("oidc", h.conn.ID)}
	if h.con.ssoSatisfied(r, v, oc) {
		t.Fatal("platform session satisfied enforcement")
	}
	v.Session = sess("oidc", c.ID)
	if !h.con.ssoSatisfied(r, v, oc) {
		t.Fatal("org session refused")
	}
	v.Session = sess("passkey", 0)
	if h.con.ssoSatisfied(r, v, oc) {
		t.Fatal("passkey developer satisfied enforcement")
	}
	oc.Role = identity.RoleOwner
	if !h.con.ssoSatisfied(r, v, oc) {
		t.Fatal("owner passkey break-glass refused")
	}
	oc.Role = identity.RoleDeveloper
	v.User.PlatformAdmin = true
	if !h.con.ssoSatisfied(r, v, oc) {
		t.Fatal("platform admin refused")
	}
}

// TestSessionSatisfiesTwoEnforcedOrgs covers the multi-org limit: signing in
// to a second enforced org's SSO keeps access to the first.
func TestSessionSatisfiesTwoEnforcedOrgs(t *testing.T) {
	h := newHarness(t, open)
	acme, idpA, _ := h.orgSSO(t)
	owner := h.user("owner@beta.example")
	beta := h.org("beta", owner)
	d, _ := h.ids.AddDomain(h.ctx, beta.ID, "beta.example")
	h.ids.MarkDomainVerified(h.ctx, beta.ID, d.ID)
	h.ids.UpdateOrgSettings(h.ctx, beta.ID, identity.OrgSettings{Name: "Beta", SSOEnforced: true, DefaultRole: identity.RoleViewer})
	idpB := authtest.NewIdP(t)
	if _, err := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: beta.ID, Slug: "beta-sso", Kind: identity.KindOIDC, Preset: "okta", Name: "Beta SSO",
		Enabled: true, Issuer: idpB.Issuer, ClientID: idpB.ClientID, ClientSecret: idpB.ClientSecret}); err != nil {
		t.Fatal(err)
	}
	// A consultant who works for both orgs, with an account in each IdP.
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "c1", Email: "consultant@personal.example", EmailVerified: true})
	u, _ := h.ids.UserByEmail(h.ctx, "consultant@personal.example")
	h.ids.SetMembership(h.ctx, acme.ID, u.ID, identity.RoleDeveloper, "manual")
	h.ids.SetMembership(h.ctx, beta.ID, u.ID, identity.RoleDeveloper, "manual")
	idpA.SetUser(authtest.User{Subject: "a-consultant", Email: "consultant@acme.example"})
	b.follow(b.post("/console/account/links/acme-sso", nil, true), 2)
	idpB.SetUser(authtest.User{Subject: "b-consultant", Email: "consultant@beta.example"})
	b.follow(b.post("/console/account/links/beta-sso", nil, true), 2)

	b.follow(b.get("/auth/oidc/acme-sso/start"), 3)
	if r := b.get("/console/orgs/acme/keys"); r.Status != http.StatusOK {
		t.Fatalf("acme after acme SSO: %d", r.Status)
	}
	b.follow(b.get("/auth/oidc/beta-sso/start"), 3)
	if r := b.get("/console/orgs/beta/keys"); r.Status != http.StatusOK {
		t.Fatalf("beta after beta SSO: %d", r.Status)
	}
	if r := b.get("/console/orgs/acme/keys"); r.Status != http.StatusOK {
		t.Fatalf("acme lost after beta SSO: %d", r.Status)
	}
	// Proofs never move to another person's session.
	other := h.browser()
	other.mustLogin(authtest.User{Subject: "o1", Email: "other@personal.example", EmailVerified: true})
	ou, _ := h.ids.UserByEmail(h.ctx, "other@personal.example")
	h.ids.SetMembership(h.ctx, acme.ID, ou.ID, identity.RoleDeveloper, "manual")
	if r := other.get("/console/orgs/acme/keys"); r.Status != http.StatusForbidden {
		t.Fatalf("other user reached acme: %d", r.Status)
	}
}
