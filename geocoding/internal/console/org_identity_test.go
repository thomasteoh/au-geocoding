package console

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
	"augeocoding/internal/samlsp"
)

// signIn logs a browser in as an existing user (the test IdP trusts verified
// email, so the login links to the user).
func (h *harness) signIn(u identity.User) *browser {
	h.t.Helper()
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "sub-" + u.Email, Email: u.Email, EmailVerified: true})
	return b
}

// addMember adds u to org with role.
func (h *harness) addMember(org identity.Org, u identity.User, role identity.Role) {
	h.t.Helper()
	if err := h.ids.SetMembership(h.ctx, org.ID, u.ID, role, "manual"); err != nil {
		h.t.Fatal(err)
	}
}

// idpMetadata builds usable SAML IdP metadata with a fresh signing cert.
func idpMetadata(t *testing.T, entityID string) string {
	t.Helper()
	_, certPEM, err := samlsp.NewKeyPair("idp")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(certPEM))
	return `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + entityID + `">
 <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(blk.Bytes) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
  <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
 </md:IDPSSODescriptor>
</md:EntityDescriptor>`
}

func idOf(t *testing.T, loc, prefix string) string {
	t.Helper()
	if !strings.HasPrefix(loc, prefix) {
		t.Fatalf("redirect %q, want prefix %q", loc, prefix)
	}
	return strings.TrimPrefix(loc, prefix)
}

func oidcForm(name, secret string) url.Values {
	return url.Values{"kind": {"oidc"}, "preset": {"okta"}, "name": {name}, "issuer": {"https://acme.okta.example/oauth2/default"},
		"client_id": {"cid-1"}, "client_secret": {secret}, "scopes": {"offline_access"}, "groups_claim": {"grp"}, "enabled": {"1"}}
}

func TestOrgOIDCConnectionLifecycle(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	b := h.signIn(owner)

	if r := b.get("/console/orgs/acme/sso"); r.Status != http.StatusOK || !strings.Contains(r.Body, h.srv.URL+"/auth/oidc/callback") {
		t.Fatalf("sso page: %d", r.Status)
	}
	if r := b.get("/console/orgs/acme/sso/new?kind=oidc"); r.Status != http.StatusOK || !strings.Contains(r.Body, "https://{your-org}.okta.com/oauth2/default") {
		t.Fatalf("new form: %d", r.Status)
	}
	// trust_email is ignored for org connections.
	f := oidcForm("Okta", "top-secret-value")
	f.Set("trust_email", "1")
	r := b.post("/console/orgs/acme/sso", f, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	id := idOf(t, r.Location, "/console/orgs/acme/sso/")
	conns, _ := h.ids.Connections(h.ctx, org.ID)
	if len(conns) != 1 {
		t.Fatalf("connections: %+v", conns)
	}
	c := conns[0]
	if c.Slug != "acme-okta" || c.ClientSecret != "top-secret-value" || c.TrustEmail || c.Preset != "okta" || !c.Enabled ||
		strings.Join(c.Scopes, " ") != "openid email profile groups offline_access" || c.GroupsClaim != "grp" {
		t.Fatalf("saved: %+v", c)
	}

	// The edit page shows IdP values but never the secret.
	r = b.get("/console/orgs/acme/sso/" + id)
	if r.Status != http.StatusOK || strings.Contains(r.Body, "top-secret-value") ||
		!strings.Contains(r.Body, h.srv.URL+"/auth/oidc/acme-okta/backchannel-logout") || !strings.Contains(r.Body, "/auth/oidc/acme-okta/start") {
		t.Fatalf("edit page: %d secret-leak=%v", r.Status, strings.Contains(r.Body, "top-secret-value"))
	}

	// Same name again gets a unique slug.
	r = b.post("/console/orgs/acme/sso", oidcForm("Okta", "s2"), true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("second create: %d", r.Status)
	}
	if _, err := h.ids.ConnectionBySlug(h.ctx, "acme-okta-2"); err != nil {
		t.Fatalf("uniquified slug: %v", err)
	}

	// Edit with a blank secret keeps it; disabling ends the connection's sessions.
	_, _, err := h.ids.CreateSession(h.ctx, identity.NewSession{UserID: owner.ID, ConnectionID: c.ID, Method: "oidc"}, h.con.Cfg.Session)
	if err != nil {
		t.Fatal(err)
	}
	f = oidcForm("Okta Renamed", "")
	f.Del("enabled")
	f.Del("kind")
	r = b.post("/console/orgs/acme/sso/"+id, f, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("update: %d %s", r.Status, r.Body)
	}
	c2, _ := h.ids.OrgConnection(h.ctx, org.ID, c.ID)
	if c2.Name != "Okta Renamed" || c2.Slug != "acme-okta" || c2.ClientSecret != "top-secret-value" || c2.Enabled {
		t.Fatalf("updated: %+v", c2)
	}
	if n := countConnSessions(h, c.ID); n != 0 {
		t.Fatalf("sessions after disable: %d", n)
	}
	// A non-https issuer is refused.
	f = oidcForm("Okta", "")
	f.Set("issuer", "http://acme.okta.example")
	if r := b.post("/console/orgs/acme/sso/"+id, f, true); r.Status != http.StatusBadRequest {
		t.Fatalf("http issuer: %d", r.Status)
	}

	// Delete ends sessions and removes the row.
	h.ids.CreateSession(h.ctx, identity.NewSession{UserID: owner.ID, ConnectionID: c.ID, Method: "oidc"}, h.con.Cfg.Session)
	if r := b.post("/console/orgs/acme/sso/"+id+"/delete", nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.Status)
	}
	if _, err := h.ids.OrgConnection(h.ctx, org.ID, c.ID); err != identity.ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	if n := countUserSessionsVia(h, owner.ID, "oidc"); n != 1 { // only the browser's own session remains
		t.Fatalf("sessions after delete: %d", n)
	}

	events, _ := h.ids.AuditLog(h.ctx, org.ID, 0, 50)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
		if strings.Contains(e.Detail+e.Target, "top-secret-value") {
			t.Fatalf("secret in audit: %+v", e)
		}
	}
	for _, a := range []string{"connection.create", "connection.update", "connection.delete"} {
		if !seen[a] {
			t.Fatalf("missing audit %s: %v", a, seen)
		}
	}
}

func countConnSessions(h *harness, connID int64) int {
	var n int
	h.ids.DB().QueryRowContext(h.ctx, `SELECT COUNT(*) FROM sessions WHERE connection_id=?`, connID).Scan(&n)
	return n
}

func countUserSessionsVia(h *harness, userID int64, method string) int {
	var n int
	h.ids.DB().QueryRowContext(h.ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=? AND method=?`, userID, method).Scan(&n)
	return n
}

func TestOrgGitHubConnection(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	b := h.signIn(owner)
	r := b.post("/console/orgs/acme/sso", url.Values{"kind": {"github"}, "name": {"GitHub"}, "client_id": {"Iv1.x"}, "client_secret": {"gh-secret"},
		"allowed_orgs": {"acme-inc  acme-labs"}, "issuer": {"https://github.acme.example/"}, "enabled": {"1"}}, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	c, err := h.ids.ConnectionBySlug(h.ctx, "acme-github")
	if err != nil || c.OrgID != org.ID || c.Kind != identity.KindGitHub || strings.Join(c.AllowedOrgs, ",") != "acme-inc,acme-labs" ||
		c.Issuer != "https://github.acme.example" || c.ClientSecret != "gh-secret" {
		t.Fatalf("github: %+v %v", c, err)
	}
	if r := b.get(r.Location); strings.Contains(r.Body, "gh-secret") {
		t.Fatal("secret rendered")
	}
}

func TestOrgSAMLConnection(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	b := h.signIn(owner)

	bad := url.Values{"kind": {"saml"}, "name": {"Bad"}, "metadata": {"<not-metadata/>"}}
	if r := b.post("/console/orgs/acme/sso", bad, true); r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "not usable") {
		t.Fatalf("bad metadata: %d", r.Status)
	}

	md := idpMetadata(t, "https://idp.example/entity")
	r := b.post("/console/orgs/acme/sso", url.Values{"kind": {"saml"}, "name": {"Corp SAML"}, "metadata": {md},
		"email_attr": {"mail"}, "groups_attr": {"memberOf"}, "enabled": {"1"}}, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	c, err := h.ids.ConnectionBySlug(h.ctx, "acme-corp-saml")
	if err != nil || c.OrgID != org.ID || c.SAMLSPKey == "" || c.SAMLSPCert == "" || c.SAMLIdPMetadata != md || c.SAMLEmailAttr != "mail" {
		t.Fatalf("saml: %+v %v", c.Slug, err)
	}
	page := b.get(r.Location)
	if page.Status != http.StatusOK || strings.Contains(page.Body, "PRIVATE KEY") ||
		!strings.Contains(page.Body, h.srv.URL+"/auth/saml/acme-corp-saml/acs") || !strings.Contains(page.Body, h.srv.URL+"/auth/saml/acme-corp-saml/metadata") {
		t.Fatalf("saml page: %d", page.Status)
	}

	// Editing without new metadata keeps the stored metadata and key pair;
	// a metadata URL is fetched with the console's HTTP client.
	id := strings.TrimPrefix(r.Location, "/console/orgs/acme/sso/")
	md2 := idpMetadata(t, "https://idp.example/entity2")
	mdSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, md2) }))
	defer mdSrv.Close()
	h.con.HTTP = mdSrv.Client()
	r = b.post("/console/orgs/acme/sso/"+id, url.Values{"name": {"Corp SAML"}, "email_attr": {"mail"}, "enabled": {"1"}}, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("update: %d %s", r.Status, r.Body)
	}
	c2, _ := h.ids.OrgConnection(h.ctx, org.ID, c.ID)
	if c2.SAMLIdPMetadata != md || c2.SAMLSPKey != c.SAMLSPKey || c2.SAMLSPCert != c.SAMLSPCert {
		t.Fatal("update lost metadata or keys")
	}
	r = b.post("/console/orgs/acme/sso/"+id, url.Values{"name": {"Corp SAML"}, "metadata_url": {mdSrv.URL + "/md"}, "enabled": {"1"}}, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("update via URL: %d %s", r.Status, r.Body)
	}
	c3, _ := h.ids.OrgConnection(h.ctx, org.ID, c.ID)
	if c3.SAMLIdPMetadata != md2 {
		t.Fatal("metadata URL not used")
	}
	if r := b.post("/console/orgs/acme/sso/"+id, url.Values{"name": {"Corp SAML"}, "metadata_url": {"http://idp.example/md"}}, true); r.Status != http.StatusBadRequest {
		t.Fatalf("http metadata URL: %d", r.Status)
	}
}

func TestGroupMappings(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	admin := h.user("admin@acme.example")
	org := h.org("acme", owner)
	h.addMember(org, admin, identity.RoleAdmin)
	c, err := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: org.ID, Slug: "acme-okta", Kind: identity.KindOIDC, Preset: "okta", Name: "Okta",
		Enabled: true, Issuer: "https://acme.okta.example", ClientID: "x", ClientSecret: "y"})
	if err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/console/orgs/acme/sso/%d/mappings", c.ID)

	ab := h.signIn(admin)
	ab.post(base, url.Values{"group": {"geo-devs"}, "role": {"developer"}}, true)
	ab.post(base, url.Values{"group": {"geo-owners"}, "role": {"owner"}}, true) // refused: admin cannot map to owner
	ab.post("/console/orgs/acme/scim/mappings", url.Values{"group": {"SCIM Admins"}, "role": {"admin"}}, true)
	ms, _ := h.ids.GroupMappings(h.ctx, org.ID)
	if len(ms) != 2 {
		t.Fatalf("mappings: %+v", ms)
	}
	ob := h.signIn(owner)
	ob.post(base, url.Values{"group": {"geo-owners"}, "role": {"owner"}}, true)
	ms, _ = h.ids.GroupMappings(h.ctx, org.ID)
	var dev, own, scim identity.GroupMapping
	for _, m := range ms {
		switch m.Group {
		case "geo-devs":
			dev = m
		case "geo-owners":
			own = m
		case "SCIM Admins":
			scim = m
		}
	}
	if dev.ConnectionID != c.ID || dev.Source != identity.SourceSSO || own.Role != identity.RoleOwner || scim.Source != identity.SourceSCIM {
		t.Fatalf("mappings: %+v", ms)
	}
	if r := ab.get(fmt.Sprintf("/console/orgs/acme/sso/%d", c.ID)); !strings.Contains(r.Body, "geo-devs") {
		t.Fatal("mapping not listed")
	}
	// Admin cannot delete the owner mapping; deleting a SCIM mapping through
	// the SSO URL (wrong source) is not found.
	ab.post(fmt.Sprintf("%s/%d/delete", base, own.ID), nil, true)
	if r := ab.post(fmt.Sprintf("%s/%d/delete", base, scim.ID), nil, true); r.Status != http.StatusNotFound {
		t.Fatalf("scim mapping via sso url: %d", r.Status)
	}
	ab.post(fmt.Sprintf("%s/%d/delete", base, dev.ID), nil, true)
	ab.post(fmt.Sprintf("/console/orgs/acme/scim/mappings/%d/delete", scim.ID), nil, true)
	ms, _ = h.ids.GroupMappings(h.ctx, org.ID)
	if len(ms) != 1 || ms[0].ID != own.ID {
		t.Fatalf("after deletes: %+v", ms)
	}
	events, _ := h.ids.AuditLog(h.ctx, org.ID, 0, 50)
	seen := map[string]int{}
	for _, e := range events {
		seen[e.Action]++
	}
	if seen["mapping.add"] != 3 || seen["mapping.delete"] != 2 {
		t.Fatalf("audit: %v", seen)
	}
}

func TestSCIMTokens(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	b := h.signIn(owner)
	r := b.get("/console/orgs/acme/scim")
	if r.Status != http.StatusOK || !strings.Contains(r.Body, h.srv.URL+"/scim/v2") {
		t.Fatalf("scim page: %d", r.Status)
	}
	r = b.post("/console/orgs/acme/scim/tokens", url.Values{"label": {"Entra"}}, true)
	m := regexpFind(`augscim_[A-Za-z0-9_-]+`, r.Body)
	if r.Status != http.StatusOK || m == "" {
		t.Fatalf("create: %d", r.Status)
	}
	if got, err := h.ids.AuthenticateSCIM(h.ctx, m); err != nil || got != org.ID {
		t.Fatalf("token does not authenticate: %v", err)
	}
	if r := b.get("/console/orgs/acme/scim"); strings.Contains(r.Body, m) {
		t.Fatal("raw token shown again")
	}
	toks, _ := h.ids.SCIMTokens(h.ctx, org.ID)
	if r := b.post(fmt.Sprintf("/console/orgs/acme/scim/tokens/%d/revoke", toks[0].ID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("revoke: %d", r.Status)
	}
	if _, err := h.ids.AuthenticateSCIM(h.ctx, m); err == nil {
		t.Fatal("revoked token still works")
	}
	events, _ := h.ids.AuditLog(h.ctx, org.ID, 0, 50)
	for _, e := range events {
		if strings.Contains(e.Detail+e.Target, m) {
			t.Fatal("raw token in audit")
		}
	}
	if len(events) < 2 || events[0].Action != "scim_token.revoke" || events[1].Action != "scim_token.create" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestJWTIssuers(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	b := h.signIn(owner)
	if r := b.get("/console/orgs/acme/tokens"); r.Status != http.StatusOK || !strings.Contains(r.Body, "Authorization: Bearer") {
		t.Fatalf("tokens page: %d", r.Status)
	}
	f := url.Values{"issuer": {"https://login.example/tenant"}, "audience": {"api://geo"}, "scope_prefix": {"geo."},
		"allowed_subjects": {"client-a\nclient-b client-c"}, "enabled": {"1"}}
	if r := b.post("/console/orgs/acme/tokens", f, true); r.Status != http.StatusSeeOther {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	if r := b.post("/console/orgs/acme/tokens", f, true); r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "already registered") {
		t.Fatalf("duplicate: %d", r.Status)
	}
	bad := url.Values{"issuer": {"https://login.example/tenant"}, "audience": {""}}
	if r := b.post("/console/orgs/acme/tokens", bad, true); r.Status != http.StatusBadRequest {
		t.Fatalf("no audience: %d", r.Status)
	}
	list, _ := h.ids.JWTIssuers(h.ctx, org.ID)
	if len(list) != 1 || len(list[0].AllowedSubjects) != 3 || list[0].ScopePrefix != "geo." || !list[0].Enabled {
		t.Fatalf("issuers: %+v", list)
	}
	id := list[0].ID
	if r := b.get(fmt.Sprintf("/console/orgs/acme/tokens/%d", id)); r.Status != http.StatusOK || !strings.Contains(r.Body, "client-b") {
		t.Fatalf("edit page: %d", r.Status)
	}
	f.Set("audience", "api://geo2")
	f.Del("enabled")
	if r := b.post(fmt.Sprintf("/console/orgs/acme/tokens/%d", id), f, true); r.Status != http.StatusSeeOther {
		t.Fatalf("update: %d %s", r.Status, r.Body)
	}
	j, _ := h.ids.OrgJWTIssuer(h.ctx, org.ID, id)
	if j.Audience != "api://geo2" || j.Enabled {
		t.Fatalf("updated: %+v", j)
	}
	if r := b.post(fmt.Sprintf("/console/orgs/acme/tokens/%d/delete", id), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.Status)
	}
	events, _ := h.ids.AuditLog(h.ctx, org.ID, 0, 50)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
	}
	if !seen["jwt_issuer.create"] || !seen["jwt_issuer.update"] || !seen["jwt_issuer.delete"] {
		t.Fatalf("audit: %v", seen)
	}
}

// TestIdentityPagesCrossOrg is A5 for every object type on these pages: an
// admin of org A uses org A's URLs with org B's IDs.
func TestIdentityPagesCrossOrg(t *testing.T) {
	h := newHarness(t, open)
	alice, bob := h.user("alice@a.example"), h.user("bob@b.example")
	orgA, orgB := h.org("org-a", alice), h.org("org-b", bob)
	connA, _ := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: orgA.ID, Slug: "org-a-idp", Kind: identity.KindOIDC, Preset: "generic", Name: "A",
		Enabled: true, Issuer: "https://a.example", ClientID: "a", ClientSecret: "a"})
	connB, err := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: orgB.ID, Slug: "org-b-idp", Kind: identity.KindOIDC, Preset: "generic", Name: "B",
		Enabled: true, Issuer: "https://b.example", ClientID: "b", ClientSecret: "b-secret"})
	if err != nil {
		t.Fatal(err)
	}
	mapB, _ := h.ids.AddGroupMapping(h.ctx, identity.GroupMapping{OrgID: orgB.ID, Source: identity.SourceSSO, ConnectionID: connB.ID, Group: "g", Role: identity.RoleViewer})
	scimMapB, _ := h.ids.AddGroupMapping(h.ctx, identity.GroupMapping{OrgID: orgB.ID, Source: identity.SourceSCIM, Group: "s", Role: identity.RoleViewer})
	tokB, _, _ := h.ids.CreateSCIMToken(h.ctx, orgB.ID, "b")
	issB, _ := h.ids.SaveJWTIssuer(h.ctx, identity.JWTIssuer{OrgID: orgB.ID, Issuer: "https://b.example", Audience: "b", Enabled: true})

	b := h.signIn(alice)
	gets := []string{
		fmt.Sprintf("/console/orgs/org-a/sso/%d", connB.ID),
		fmt.Sprintf("/console/orgs/org-a/tokens/%d", issB.ID),
		"/console/orgs/org-b/sso", "/console/orgs/org-b/scim", "/console/orgs/org-b/tokens",
	}
	for _, p := range gets {
		if r := b.get(p); r.Status != http.StatusNotFound || strings.Contains(r.Body, "b-secret") {
			t.Errorf("GET %s: %d", p, r.Status)
		}
	}
	posts := map[string]url.Values{
		fmt.Sprintf("/console/orgs/org-a/sso/%d", connB.ID):                             {"name": {"pwned"}, "preset": {"generic"}, "issuer": {"https://evil.example"}, "client_id": {"x"}, "enabled": {"1"}},
		fmt.Sprintf("/console/orgs/org-a/sso/%d/delete", connB.ID):                      nil,
		fmt.Sprintf("/console/orgs/org-a/sso/%d/mappings", connB.ID):                    {"group": {"x"}, "role": {"admin"}},
		fmt.Sprintf("/console/orgs/org-a/sso/%d/mappings/%d/delete", connA.ID, mapB.ID): nil,
		fmt.Sprintf("/console/orgs/org-a/sso/%d/mappings/%d/delete", connB.ID, mapB.ID): nil,
		fmt.Sprintf("/console/orgs/org-a/scim/mappings/%d/delete", scimMapB.ID):         nil,
		fmt.Sprintf("/console/orgs/org-a/scim/tokens/%d/revoke", tokB.ID):               nil,
		fmt.Sprintf("/console/orgs/org-a/tokens/%d", issB.ID):                           {"issuer": {"https://evil.example"}, "audience": {"x"}},
		fmt.Sprintf("/console/orgs/org-a/tokens/%d/delete", issB.ID):                    nil,
		"/console/orgs/org-b/sso":         oidcForm("Evil", "x"),
		"/console/orgs/org-b/scim/tokens": {"label": {"evil"}},
		"/console/orgs/org-b/tokens":      {"issuer": {"https://evil.example"}, "audience": {"x"}},
	}
	for p, f := range posts {
		if r := b.post(p, f, true); r.Status != http.StatusNotFound {
			t.Errorf("POST %s: %d", p, r.Status)
		}
	}
	// Nothing in org B changed.
	if c, _ := h.ids.OrgConnection(h.ctx, orgB.ID, connB.ID); c.Name != "B" || c.Issuer != "https://b.example" {
		t.Errorf("conn B changed: %+v", c)
	}
	if ms, _ := h.ids.GroupMappings(h.ctx, orgB.ID); len(ms) != 2 {
		t.Errorf("mappings B: %+v", ms)
	}
	if ms, _ := h.ids.GroupMappings(h.ctx, orgA.ID); len(ms) != 0 {
		t.Errorf("mapping created in A: %+v", ms)
	}
	if toks, _ := h.ids.SCIMTokens(h.ctx, orgB.ID); len(toks) != 1 || toks[0].Revoked != nil {
		t.Errorf("scim B: %+v", toks)
	}
	if j, err := h.ids.OrgJWTIssuer(h.ctx, orgB.ID, issB.ID); err != nil || j.Audience != "b" {
		t.Errorf("issuer B: %+v %v", j, err)
	}
	if cs, _ := h.ids.Connections(h.ctx, orgB.ID); len(cs) != 1 {
		t.Errorf("connections B: %d", len(cs))
	}
}

func TestIdentityPagesNeedAdmin(t *testing.T) {
	h := newHarness(t, open)
	owner, dev := h.user("owner@acme.example"), h.user("dev@acme.example")
	org := h.org("acme", owner)
	h.addMember(org, dev, identity.RoleDeveloper)
	b := h.signIn(dev)
	for _, p := range []string{"/console/orgs/acme/sso", "/console/orgs/acme/sso/new", "/console/orgs/acme/scim", "/console/orgs/acme/tokens"} {
		if r := b.get(p); r.Status != http.StatusForbidden {
			t.Errorf("GET %s: %d", p, r.Status)
		}
	}
	for p, f := range map[string]url.Values{
		"/console/orgs/acme/sso":         oidcForm("X", "y"),
		"/console/orgs/acme/scim/tokens": {"label": {"x"}},
		"/console/orgs/acme/tokens":      {"issuer": {"https://x.example"}, "audience": {"x"}},
	} {
		if r := b.post(p, f, true); r.Status != http.StatusForbidden {
			t.Errorf("POST %s: %d", p, r.Status)
		}
	}
	if toks, _ := h.ids.SCIMTokens(h.ctx, org.ID); len(toks) != 0 {
		t.Fatal("developer created a SCIM token")
	}
	// An admin without the CSRF token is refused too.
	ob := h.signIn(owner)
	if r := ob.post("/console/orgs/acme/scim/tokens", url.Values{"label": {"x"}}, false); r.Status != http.StatusForbidden {
		t.Fatalf("no csrf: %d", r.Status)
	}
}

func regexpFind(pat, s string) string {
	return regexp.MustCompile(pat).FindString(s)
}
