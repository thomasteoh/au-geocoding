package console

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
)

// platformAdmin creates a platform admin and signs them in.
func (h *harness) platformAdmin(email string) (identity.User, *browser) {
	h.t.Helper()
	u := h.user(email)
	if err := h.ids.SetPlatformAdmin(h.ctx, u.ID, true); err != nil {
		h.t.Fatal(err)
	}
	u.PlatformAdmin = true
	return u, h.signIn(u)
}

func TestAdminPagesHiddenFromOthers(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	victim := h.user("victim@example.com")
	b := h.signIn(owner)
	for _, p := range []string{"/console/admin", "/console/admin/orgs", "/console/admin/connections", "/console/admin/connections/new",
		fmt.Sprintf("/console/admin/connections/%d", h.conn.ID), "/console/admin/users"} {
		if r := b.get(p); r.Status != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, r.Status)
		}
	}
	for p, f := range map[string]url.Values{
		fmt.Sprintf("/console/admin/orgs/%d/tier", org.ID):             {"tier": {"batch"}},
		fmt.Sprintf("/console/admin/users/%d/admin", owner.ID):         {"admin": {"1"}},
		fmt.Sprintf("/console/admin/users/%d/status", victim.ID):       {"status": {"suspended"}},
		fmt.Sprintf("/console/admin/connections/%d/delete", h.conn.ID): nil,
		"/console/admin/connections":                                   oidcForm("Evil", "x"),
	} {
		if r := b.post(p, f, true); r.Status != http.StatusNotFound {
			t.Errorf("POST %s: %d", p, r.Status)
		}
	}
	if u, _ := h.ids.UserByID(h.ctx, owner.ID); u.PlatformAdmin {
		t.Fatal("self-promotion worked")
	}
	if u, _ := h.ids.UserByID(h.ctx, victim.ID); !u.Active() {
		t.Fatal("suspension worked")
	}
	if o, _ := h.ids.OrgByID(h.ctx, org.ID); o.Tier == "batch" {
		t.Fatal("tier changed")
	}
}

func TestAdminOrgTier(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	key, _, err := h.keys.IssueKeyWith(publicapi.IssueOptions{Label: "k", Tier: publicapi.QuotaTier(org.Tier), OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	_, b := h.platformAdmin("root@example.com")
	if r := b.get("/console/admin"); r.Status != http.StatusOK || !strings.Contains(r.Body, "/console/admin/users") {
		t.Fatalf("overview: %d", r.Status)
	}
	if r := b.get("/console/admin/orgs"); r.Status != http.StatusOK || !strings.Contains(r.Body, "acme") {
		t.Fatalf("orgs: %d", r.Status)
	}
	if r := b.post(fmt.Sprintf("/console/admin/orgs/%d/tier", org.ID), url.Values{"tier": {"anonymous"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("bad tier: %d", r.Status)
	}
	if r := b.post(fmt.Sprintf("/console/admin/orgs/%d/tier", org.ID), url.Values{"tier": {"batch"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("tier: %d", r.Status)
	}
	if o, _ := h.ids.OrgByID(h.ctx, org.ID); o.Tier != "batch" {
		t.Fatalf("org tier: %s", o.Tier)
	}
	if k, _ := h.keys.OrgKey(org.ID, key.ID); k.Tier != publicapi.TierBatch {
		t.Fatalf("key tier: %v", k.Tier)
	}
	if r := b.post("/console/admin/orgs/99999/tier", url.Values{"tier": {"batch"}}, true); r.Status != http.StatusNotFound {
		t.Fatalf("missing org: %d", r.Status)
	}
	events, _ := h.ids.AuditLog(h.ctx, 0, 0, 10)
	if len(events) == 0 || events[0].Action != "org.tier" {
		t.Fatalf("audit: %+v", events)
	}
}

func TestAdminPlatformConnections(t *testing.T) {
	h := newHarness(t, open)
	_, b := h.platformAdmin("root@example.com")
	if r := b.get("/console/admin/connections"); r.Status != http.StatusOK || !strings.Contains(r.Body, "test-idp") {
		t.Fatalf("list: %d", r.Status)
	}
	if r := b.get("/console/admin/connections/new?kind=oidc"); r.Status != http.StatusOK || !strings.Contains(r.Body, "Trust email") {
		t.Fatalf("new: %d", r.Status)
	}
	f := oidcForm("Corp Google", "plat-secret")
	f.Set("preset", "google")
	f.Set("trust_email", "1")
	r := b.post("/console/admin/connections", f, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	c, err := h.ids.ConnectionBySlug(h.ctx, "corp-google")
	if err != nil || c.OrgID != 0 || !c.TrustEmail || c.ClientSecret != "plat-secret" {
		t.Fatalf("platform conn: %+v %v", c.Slug, err)
	}
	if r := b.get(r.Location); r.Status != http.StatusOK || strings.Contains(r.Body, "plat-secret") {
		t.Fatalf("edit page: %d", r.Status)
	}
	// Org connections are not reachable through the platform pages.
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	oc, _ := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: org.ID, Slug: "acme-x", Kind: identity.KindOIDC, Preset: "generic", Name: "X",
		Enabled: true, Issuer: "https://x.example", ClientID: "x"})
	if r := b.get(fmt.Sprintf("/console/admin/connections/%d", oc.ID)); r.Status != http.StatusNotFound {
		t.Fatalf("org conn via admin: %d", r.Status)
	}

	// Managed connections are read-only.
	m, _ := h.ids.SaveConnection(h.ctx, identity.Connection{Slug: "managed", Kind: identity.KindGitHub, Name: "Managed GitHub", Enabled: true,
		ClientID: "m", ClientSecret: "m", Managed: true})
	if r := b.get(fmt.Sprintf("/console/admin/connections/%d", m.ID)); r.Status != http.StatusOK || !strings.Contains(r.Body, "read-only") {
		t.Fatalf("managed page: %d", r.Status)
	}
	if r := b.post(fmt.Sprintf("/console/admin/connections/%d", m.ID), url.Values{"name": {"Hacked"}, "client_id": {"m"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("managed update: %d", r.Status)
	}
	if r := b.post(fmt.Sprintf("/console/admin/connections/%d/delete", m.ID), nil, true); r.Status != http.StatusForbidden {
		t.Fatalf("managed delete: %d", r.Status)
	}

	// Deleting a platform connection ends its sessions, including ours.
	other := h.signIn(h.user("someone@example.com"))
	if r := b.post(fmt.Sprintf("/console/admin/connections/%d/delete", h.conn.ID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.Status)
	}
	if r := other.get("/console/account"); r.Status != http.StatusSeeOther {
		t.Fatalf("session survived connection delete: %d", r.Status)
	}
	events, _ := h.ids.AuditLog(h.ctx, 0, 0, 50)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
		if strings.Contains(e.Detail, "plat-secret") {
			t.Fatal("secret in audit")
		}
	}
	if !seen["connection.create"] || !seen["connection.delete"] {
		t.Fatalf("audit: %v", seen)
	}
}

func TestAdminSAMLMetadataFetchUsesConsoleClient(t *testing.T) {
	h := newHarness(t, open)
	_, b := h.platformAdmin("root@example.com")
	md := idpMetadata(t, "https://idp.example/e")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, md) }))
	defer srv.Close()
	h.con.HTTP = srv.Client()
	r := b.post("/console/admin/connections", url.Values{"kind": {"saml"}, "name": {"Partner"}, "metadata_url": {srv.URL}, "enabled": {"1"}}, true)
	if r.Status != http.StatusSeeOther {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	c, err := h.ids.ConnectionBySlug(h.ctx, "partner")
	if err != nil || c.SAMLIdPMetadata != md || c.SAMLSPKey == "" || c.OrgID != 0 {
		t.Fatalf("saml: %v", err)
	}
}

func TestAdminUsers(t *testing.T) {
	h := newHarness(t, open)
	root, b := h.platformAdmin("root@example.com")
	target := h.user("target@example.com")
	tb := h.signIn(target)

	if r := b.get("/console/admin/users?q=target"); r.Status != http.StatusOK || !strings.Contains(r.Body, "<td>target@example.com</td>") || strings.Contains(r.Body, "<td>root@example.com</td>") {
		t.Fatalf("search: %d", r.Status)
	}
	// Suspend ends the user's sessions; reactivate restores status.
	if r := b.post(fmt.Sprintf("/console/admin/users/%d/status", target.ID), url.Values{"status": {"suspended"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("suspend: %d", r.Status)
	}
	if u, _ := h.ids.UserByID(h.ctx, target.ID); u.Status != identity.StatusSuspended {
		t.Fatalf("status: %s", u.Status)
	}
	if r := tb.get("/console/account"); r.Status != http.StatusSeeOther {
		t.Fatalf("suspended session survived: %d", r.Status)
	}
	b.post(fmt.Sprintf("/console/admin/users/%d/status", target.ID), url.Values{"status": {"active"}}, true)
	if u, _ := h.ids.UserByID(h.ctx, target.ID); !u.Active() {
		t.Fatal("not reactivated")
	}
	// Grant and revoke platform admin.
	b.post(fmt.Sprintf("/console/admin/users/%d/admin", target.ID), url.Values{"admin": {"1"}}, true)
	if u, _ := h.ids.UserByID(h.ctx, target.ID); !u.PlatformAdmin {
		t.Fatal("not granted")
	}
	b.post(fmt.Sprintf("/console/admin/users/%d/admin", target.ID), url.Values{"admin": {"0"}}, true)
	if u, _ := h.ids.UserByID(h.ctx, target.ID); u.PlatformAdmin {
		t.Fatal("not revoked")
	}
	// Not on yourself.
	b.post(fmt.Sprintf("/console/admin/users/%d/status", root.ID), url.Values{"status": {"suspended"}}, true)
	b.post(fmt.Sprintf("/console/admin/users/%d/admin", root.ID), url.Values{"admin": {"0"}}, true)
	if u, _ := h.ids.UserByID(h.ctx, root.ID); !u.Active() || !u.PlatformAdmin {
		t.Fatalf("self change applied: %+v", u)
	}
	if r := b.post("/console/admin/users/99999/status", url.Values{"status": {"suspended"}}, true); r.Status != http.StatusNotFound {
		t.Fatalf("missing user: %d", r.Status)
	}
	events, _ := h.ids.AuditLog(h.ctx, 0, 0, 50)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
	}
	for _, a := range []string{"user.suspend", "user.reactivate", "platform_admin.grant", "platform_admin.revoke"} {
		if !seen[a] {
			t.Fatalf("missing audit %s: %v", a, seen)
		}
	}
}
