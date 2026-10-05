package console

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"augeocoding/internal/authtest"
	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
)

// member signs a new browser in as email and gives that user role in org.
func (h *harness) member(email string, org identity.Org, role identity.Role) (*browser, identity.User) {
	h.t.Helper()
	b := h.browser()
	b.mustLogin(authtest.User{Subject: "sub-" + email, Email: email, EmailVerified: true})
	u, err := h.ids.UserByEmail(h.ctx, email)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.ids.SetMembership(h.ctx, org.ID, u.ID, role, "manual"); err != nil {
		h.t.Fatal(err)
	}
	return b, u
}

// flash follows a post/redirect/get and returns the next page's body.
func (b *browser) flash(r resp) string {
	b.h.t.Helper()
	if r.Status != http.StatusSeeOther {
		b.h.t.Fatalf("want redirect, got %d %s", r.Status, r.Body)
	}
	return b.get(r.Location).Body
}

func (h *harness) issue(org identity.Org, by identity.User, label string) publicapi.Key {
	h.t.Helper()
	k, _, err := h.keys.IssueKeyWith(publicapi.IssueOptions{Label: label, Tier: publicapi.TierDemo, Scopes: []string{"search"}, OrgID: org.ID, CreatedBy: by.ID})
	if err != nil {
		h.t.Fatal(err)
	}
	return k
}

func (h *harness) hasAudit(org identity.Org, action string) bool {
	events, _ := h.ids.AuditLog(h.ctx, org.ID, 0, 500)
	for _, e := range events {
		if e.Action == action {
			return true
		}
	}
	return false
}

var rawKeyRe = regexp.MustCompile(`<p class="secret" id="new-key">([0-9a-f]{32})</p>`)

func TestKeyCreateShownOnceAndEscaped(t *testing.T) {
	h := newHarness(t, open)
	org := h.org("acme", h.user("owner@acme.example"))
	b, dev := h.member("dev@acme.example", org, identity.RoleDeveloper)

	// The batch scope needs the batch tier.
	b.post("/console/orgs/acme/keys", url.Values{"label": {"x"}, "scope": {"batch"}}, true)
	if keys, _ := h.keys.OrgKeys(org.ID); len(keys) != 0 {
		t.Fatalf("batch key on demo tier: %+v", keys)
	}
	h.ids.SetOrgTier(h.ctx, org.ID, "batch")

	r := b.post("/console/orgs/acme/keys", url.Values{"label": {"<script>alert(1)</script>"}, "scope": {"search", "batch", "admin"}, "expires_days": {"30"}}, true)
	if r.Status != http.StatusOK {
		t.Fatalf("create: %d %s", r.Status, r.Body)
	}
	m := rawKeyRe.FindStringSubmatch(r.Body)
	if m == nil || !strings.Contains(r.Body, "X-Api-Key") {
		t.Fatalf("raw key not shown: %s", r.Body)
	}
	if strings.Contains(r.Body, "<script>alert(1)") || !strings.Contains(r.Body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("label not escaped")
	}
	k, err := h.keys.Authenticate(m[1])
	if err != nil {
		t.Fatalf("raw key does not authenticate: %v", err)
	}
	if k.OrgID != org.ID || k.CreatedBy != dev.ID || k.Tier != publicapi.TierBatch || k.Expires == nil || strings.Join(k.Scopes, " ") != "search batch" {
		t.Fatalf("issued key: %+v", k)
	}
	list := b.get("/console/orgs/acme/keys")
	if list.Status != http.StatusOK || strings.Contains(list.Body, m[1]) || !strings.Contains(list.Body, k.Prefix) {
		t.Fatalf("list page: %d leaked=%t", list.Status, strings.Contains(list.Body, m[1]))
	}
	if !h.hasAudit(org, "key.create") {
		t.Fatal("no key.create audit")
	}
	for _, bad := range []url.Values{
		{"label": {""}, "scope": {"search"}},
		{"label": {strings.Repeat("x", 101)}, "scope": {"search"}},
		{"label": {"ok"}},
		{"label": {"ok"}, "scope": {"search"}, "expires_days": {"731"}},
	} {
		if r := b.post("/console/orgs/acme/keys", bad, true); r.Status != http.StatusSeeOther {
			t.Fatalf("invalid %v: %d", bad, r.Status)
		}
	}
	if keys, _ := h.keys.OrgKeys(org.ID); len(keys) != 1 {
		t.Fatalf("invalid forms issued keys: %d", len(keys))
	}
}

func TestKeyRoles(t *testing.T) {
	h := newHarness(t, open)
	org := h.org("acme", h.user("owner@acme.example"))
	viewer, _ := h.member("viewer@acme.example", org, identity.RoleViewer)
	dev, devUser := h.member("dev@acme.example", org, identity.RoleDeveloper)
	admin, adminUser := h.member("admin@acme.example", org, identity.RoleAdmin)

	if r := viewer.get("/console/orgs/acme/keys"); r.Status != http.StatusOK || strings.Contains(r.Body, "Create a key") {
		t.Fatalf("viewer list: %d", r.Status)
	}
	if r := viewer.post("/console/orgs/acme/keys", url.Values{"label": {"x"}, "scope": {"search"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("viewer create: %d", r.Status)
	}
	adminKey := h.issue(org, adminUser, "admin key")
	devKey := h.issue(org, devUser, "dev key")
	if r := dev.post(fmt.Sprintf("/console/orgs/acme/keys/%d/revoke", adminKey.ID), nil, true); r.Status != http.StatusForbidden {
		t.Fatalf("developer revoked another's key: %d", r.Status)
	}
	if k, _ := h.keys.OrgKey(org.ID, adminKey.ID); k.Revoked != nil {
		t.Fatal("key revoked")
	}
	if r := dev.post(fmt.Sprintf("/console/orgs/acme/keys/%d/revoke", devKey.ID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("developer revoke own: %d", r.Status)
	}
	if r := admin.post(fmt.Sprintf("/console/orgs/acme/keys/%d/revoke", adminKey.ID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("admin revoke: %d", r.Status)
	}
	for _, id := range []int64{adminKey.ID, devKey.ID} {
		if k, _ := h.keys.OrgKey(org.ID, id); k.Revoked == nil {
			t.Fatalf("key %d not revoked", id)
		}
	}
	if !h.hasAudit(org, "key.revoke") {
		t.Fatal("no key.revoke audit")
	}
}

// TestCrossOrgIDs posts org B's object IDs to org A's URLs as an admin of
// A (auth.md A5).
func TestCrossOrgIDs(t *testing.T) {
	h := newHarness(t, open)
	ownerA, ownerB := h.user("owner@a.example"), h.user("owner@b.example")
	a, bOrg := h.org("org-a", ownerA), h.org("org-b", ownerB)
	admin, _ := h.member("admin@a.example", a, identity.RoleAdmin)

	bKey := h.issue(bOrg, ownerB, "b key")
	if err := h.ids.CreateInvite(h.ctx, bOrg.ID, "new@b.example", identity.RoleViewer, ownerB.ID, inviteTTL); err != nil {
		t.Fatal(err)
	}
	invites, _ := h.ids.Invites(h.ctx, bOrg.ID)
	bDomain, _ := h.ids.AddDomain(h.ctx, bOrg.ID, "b.example")
	bMember := h.user("member@b.example")
	h.ids.SetMembership(h.ctx, bOrg.ID, bMember.ID, identity.RoleViewer, "manual")
	h.con.LookupTXT = func(ctx context.Context, name string) ([]string, error) { return []string{bDomain.TXTValue()}, nil }

	for _, p := range []struct {
		path string
		form url.Values
	}{
		{fmt.Sprintf("/console/orgs/org-a/keys/%d/revoke", bKey.ID), nil},
		{fmt.Sprintf("/console/orgs/org-a/invites/%d/delete", invites[0].ID), nil},
		{fmt.Sprintf("/console/orgs/org-a/domains/%d/verify", bDomain.ID), nil},
		{fmt.Sprintf("/console/orgs/org-a/domains/%d/delete", bDomain.ID), nil},
		{fmt.Sprintf("/console/orgs/org-a/members/%d/role", bMember.ID), url.Values{"role": {"admin"}}},
		{fmt.Sprintf("/console/orgs/org-a/members/%d/remove", bMember.ID), nil},
		{fmt.Sprintf("/console/orgs/org-a/members/%d/role", ownerB.ID), url.Values{"role": {"viewer"}}},
	} {
		if r := admin.post(p.path, p.form, true); r.Status != http.StatusNotFound {
			t.Errorf("%s: %d", p.path, r.Status)
		}
	}
	// And straight at org B's URLs as a non-member.
	if r := admin.post(fmt.Sprintf("/console/orgs/org-b/keys/%d/revoke", bKey.ID), nil, true); r.Status != http.StatusNotFound {
		t.Errorf("org-b revoke as non-member: %d", r.Status)
	}

	if k, _ := h.keys.OrgKey(bOrg.ID, bKey.ID); k.Revoked != nil {
		t.Error("b key revoked")
	}
	if inv, _ := h.ids.Invites(h.ctx, bOrg.ID); len(inv) != 1 {
		t.Error("b invite deleted")
	}
	if d, err := h.ids.OrgDomain(h.ctx, bOrg.ID, bDomain.ID); err != nil || d.Verified != nil {
		t.Errorf("b domain changed: %v %+v", err, d)
	}
	if role, _ := h.ids.Role(h.ctx, bOrg.ID, bMember.ID); role != identity.RoleViewer {
		t.Errorf("b member role: %v", role)
	}
	if role, _ := h.ids.Role(h.ctx, bOrg.ID, ownerB.ID); role != identity.RoleOwner {
		t.Errorf("b owner role: %v", role)
	}
}

func TestMemberRoleRules(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	admin, adminUser := h.member("admin@acme.example", org, identity.RoleAdmin)
	dev := h.user("dev@acme.example")
	h.ids.SetMembership(h.ctx, org.ID, dev.ID, identity.RoleDeveloper, "manual")
	rolePath := func(u identity.User) string { return fmt.Sprintf("/console/orgs/acme/members/%d/role", u.ID) }

	if r := admin.post(rolePath(dev), url.Values{"role": {"owner"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("admin promoted to owner: %d", r.Status)
	}
	if r := admin.post(rolePath(owner), url.Values{"role": {"viewer"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("admin demoted owner: %d", r.Status)
	}
	if r := admin.post(fmt.Sprintf("/console/orgs/acme/members/%d/remove", owner.ID), nil, true); r.Status != http.StatusForbidden {
		t.Fatalf("admin removed owner: %d", r.Status)
	}
	if r := admin.post(rolePath(adminUser), url.Values{"role": {"viewer"}}, true); !strings.Contains(admin.flash(r), "change your own role") {
		t.Fatal("changed own role")
	}
	if r := admin.post("/console/orgs/acme/invites", url.Values{"email": {"boss@acme.example"}, "role": {"owner"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("admin invited owner: %d", r.Status)
	}
	if r := admin.post(rolePath(dev), url.Values{"role": {"admin"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("admin promote dev: %d", r.Status)
	}
	if role, _ := h.ids.Role(h.ctx, org.ID, dev.ID); role != identity.RoleAdmin {
		t.Fatalf("dev role: %v", role)
	}

	// Viewer cannot manage at all.
	viewer, _ := h.member("viewer@acme.example", org, identity.RoleViewer)
	if r := viewer.post(rolePath(dev), url.Values{"role": {"viewer"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("viewer role change: %d", r.Status)
	}
	if r := viewer.get("/console/orgs/acme/members"); r.Status != http.StatusOK || strings.Contains(r.Body, "Invite someone") || !strings.Contains(r.Body, "owner@acme.example") {
		t.Fatalf("viewer members page: %d", r.Status)
	}

	// Owners can grant and change owner.
	ob, ownerUser := h.member("owner2@acme.example", org, identity.RoleOwner)
	if r := ob.post(rolePath(adminUser), url.Values{"role": {"owner"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("owner promote: %d", r.Status)
	}
	if r := ob.post(rolePath(owner), url.Values{"role": {"developer"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("owner demote owner: %d", r.Status)
	}
	if role, _ := h.ids.Role(h.ctx, org.ID, owner.ID); role != identity.RoleDeveloper {
		t.Fatalf("demoted owner role: %v", role)
	}
	// Remaining owners: ownerUser and adminUser. Remove adminUser, then the
	// last owner cannot leave.
	if r := ob.post(fmt.Sprintf("/console/orgs/acme/members/%d/remove", adminUser.ID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("owner remove owner: %d", r.Status)
	}
	if r := ob.post("/console/orgs/acme/members/leave", nil, true); !strings.Contains(ob.flash(r), "last owner") {
		t.Fatal("last owner left")
	}
	if role, _ := h.ids.Role(h.ctx, org.ID, ownerUser.ID); role != identity.RoleOwner {
		t.Fatal("last owner gone")
	}
	// A viewer can leave.
	if r := viewer.post("/console/orgs/acme/members/leave", nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("viewer leave: %d", r.Status)
	}
	if viewer.get("/console/orgs/acme/members").Status != http.StatusNotFound {
		t.Fatal("viewer still a member")
	}
	for _, a := range []string{"member.role", "member.remove"} {
		if !h.hasAudit(org, a) {
			t.Errorf("no %s audit", a)
		}
	}
}

func TestInvites(t *testing.T) {
	h := newHarness(t, open)
	org := h.org("acme", h.user("owner@acme.example"))
	admin, _ := h.member("admin@acme.example", org, identity.RoleAdmin)
	existing := h.user("existing@example.com")

	if r := admin.post("/console/orgs/acme/invites", url.Values{"email": {"Existing@Example.com"}, "role": {"developer"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("invite existing: %d", r.Status)
	}
	// Existing accounts are invited, not added: they accept by signing in.
	if role, _ := h.ids.Role(h.ctx, org.ID, existing.ID); role != identity.RoleNone {
		t.Fatalf("existing user added without accepting: %v", role)
	}
	if inv, _ := h.ids.Invites(h.ctx, org.ID); len(inv) != 1 || inv[0].Email != "existing@example.com" {
		t.Fatalf("existing user invite: %+v", inv)
	}
	h.ids.DeleteInvite(h.ctx, org.ID, mustInviteID(t, h, org.ID, "existing@example.com"))
	if r := admin.post("/console/orgs/acme/invites", url.Values{"email": {"new@example.com"}, "role": {"viewer"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("invite new: %d", r.Status)
	}
	inv, _ := h.ids.Invites(h.ctx, org.ID)
	if len(inv) != 1 || inv[0].Email != "new@example.com" || (inv[0].Expires.Sub(inv[0].Created)-inviteTTL).Abs() > time.Second {
		t.Fatalf("invites: %+v", inv)
	}
	page := admin.get("/console/orgs/acme/members")
	if !strings.Contains(page.Body, "new@example.com") || !strings.Contains(page.Body, "admin@acme.example") {
		t.Fatal("members page missing invite or member")
	}
	if r := admin.post(fmt.Sprintf("/console/orgs/acme/invites/%d/delete", inv[0].ID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("delete invite: %d", r.Status)
	}
	if inv, _ := h.ids.Invites(h.ctx, org.ID); len(inv) != 0 {
		t.Fatal("invite not deleted")
	}
	for _, a := range []string{"invite.create", "invite.delete"} {
		if !h.hasAudit(org, a) {
			t.Errorf("no %s audit", a)
		}
	}
}

func TestDomains(t *testing.T) {
	h := newHarness(t, open)
	org := h.org("acme", h.user("owner@acme.example"))
	other := h.org("other", h.user("owner@other.example"))
	admin, _ := h.member("admin@acme.example", org, identity.RoleAdmin)
	dev, _ := h.member("dev@acme.example", org, identity.RoleDeveloper)

	if r := dev.get("/console/orgs/acme/domains"); r.Status != http.StatusForbidden {
		t.Fatalf("developer domains: %d", r.Status)
	}
	if r := admin.post("/console/orgs/acme/domains", url.Values{"domain": {"Acme.Example"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("add: %d", r.Status)
	}
	ds, _ := h.ids.Domains(h.ctx, org.ID)
	if len(ds) != 1 {
		t.Fatalf("domains: %+v", ds)
	}
	d := ds[0]
	if page := admin.get("/console/orgs/acme/domains"); !strings.Contains(page.Body, d.TXTName()) || !strings.Contains(page.Body, d.TXTValue()) {
		t.Fatal("TXT record not shown")
	}
	verify := fmt.Sprintf("/console/orgs/acme/domains/%d/verify", d.ID)

	var asked string
	h.con.LookupTXT = func(ctx context.Context, name string) ([]string, error) {
		asked = name
		return []string{"unrelated"}, nil
	}
	if r := admin.post(verify, nil, true); !strings.Contains(admin.flash(r), "No matching TXT record") {
		t.Fatal("verified without record")
	}
	if asked != d.TXTName() {
		t.Fatalf("looked up %q", asked)
	}

	// Another org verified it first.
	od, _ := h.ids.AddDomain(h.ctx, other.ID, "acme.example")
	h.ids.MarkDomainVerified(h.ctx, other.ID, od.ID)
	h.con.LookupTXT = func(ctx context.Context, name string) ([]string, error) {
		return []string{` "` + d.TXTValue() + `" `}, nil
	}
	if r := admin.post(verify, nil, true); !strings.Contains(admin.flash(r), "already verified by another organisation") {
		t.Fatal("conflict not reported")
	}
	h.ids.DeleteDomain(h.ctx, other.ID, od.ID)
	if r := admin.post(verify, nil, true); !strings.Contains(admin.flash(r), "Verified acme.example") {
		t.Fatal("not verified")
	}
	if d, _ := h.ids.OrgDomain(h.ctx, org.ID, d.ID); d.Verified == nil {
		t.Fatal("domain not marked verified")
	}
	if r := admin.post(fmt.Sprintf("/console/orgs/acme/domains/%d/delete", d.ID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("delete: %d", r.Status)
	}
	if ds, _ := h.ids.Domains(h.ctx, org.ID); len(ds) != 0 {
		t.Fatal("domain not deleted")
	}
	for _, a := range []string{"domain.add", "domain.verify", "domain.delete"} {
		if !h.hasAudit(org, a) {
			t.Errorf("no %s audit", a)
		}
	}
}

func TestAuditPaging(t *testing.T) {
	h := newHarness(t, open)
	org := h.org("acme", h.user("owner@acme.example"))
	admin, _ := h.member("admin@acme.example", org, identity.RoleAdmin)
	dev, _ := h.member("dev@acme.example", org, identity.RoleDeveloper)
	for i := 0; i < 150; i++ {
		h.ids.Audit(h.ctx, identity.AuditEvent{OrgID: org.ID, Actor: "system", Action: "test.event", Target: fmt.Sprintf("t-%03d", i)})
	}
	if r := dev.get("/console/orgs/acme/audit"); r.Status != http.StatusForbidden {
		t.Fatalf("developer audit: %d", r.Status)
	}
	r := admin.get("/console/orgs/acme/audit")
	if r.Status != http.StatusOK || !strings.Contains(r.Body, "t-149") || strings.Contains(r.Body, "t-049") {
		t.Fatalf("first page: %d", r.Status)
	}
	m := regexp.MustCompile(`href="(/console/orgs/acme/audit\?before=\d+)"`).FindStringSubmatch(r.Body)
	if m == nil {
		t.Fatal("no Older link")
	}
	r = admin.get(m[1])
	if !strings.Contains(r.Body, "t-049") || strings.Contains(r.Body, "t-050") || strings.Contains(r.Body, "audit?before=") {
		t.Fatal("second page wrong")
	}
}

func TestSettings(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	ob, owner2 := h.member("owner2@acme.example", org, identity.RoleOwner)
	admin, _ := h.member("admin@acme.example", org, identity.RoleAdmin)

	if r := admin.get("/console/orgs/acme/settings"); r.Status != http.StatusForbidden {
		t.Fatalf("admin settings: %d", r.Status)
	}
	form := url.Values{"name": {"Acme Pty Ltd"}, "jit": {"1"}, "default_role": {"developer"}, "sso_enforced": {"1"}}
	if r := ob.post("/console/orgs/acme/settings", form, true); !strings.Contains(ob.flash(r), "verify a domain") {
		t.Fatal("SSO enforced without prerequisites")
	}
	if o, _ := h.ids.OrgByID(h.ctx, org.ID); o.SSOEnforced || o.Name != "acme" {
		t.Fatalf("settings applied: %+v", o)
	}
	d, _ := h.ids.AddDomain(h.ctx, org.ID, "acme.example")
	h.ids.MarkDomainVerified(h.ctx, org.ID, d.ID)
	if r := ob.post("/console/orgs/acme/settings", form, true); !strings.Contains(ob.flash(r), "verify a domain") {
		t.Fatal("SSO enforced without a connection")
	}
	if _, err := h.ids.SaveConnection(h.ctx, identity.Connection{OrgID: org.ID, Slug: "acme-okta", Kind: identity.KindOIDC, Preset: "okta", Name: "Acme Okta",
		Enabled: true, Issuer: "https://acme.okta.example", ClientID: "x"}); err != nil {
		t.Fatal(err)
	}
	// The owner is signed in through a platform IdP, so turning enforcement
	// on would lock them out: refused.
	if r := ob.post("/console/orgs/acme/settings", form, true); !strings.Contains(ob.flash(r), "SSO connections first") {
		t.Fatal("enforcement enabled from a non-SSO session")
	}
	// A platform admin may (and is exempt from enforcement).
	h.ids.SetPlatformAdmin(h.ctx, owner2.ID, true)
	if r := ob.post("/console/orgs/acme/settings", form, true); !strings.Contains(ob.flash(r), "Settings saved") {
		t.Fatal("not saved")
	}
	o, _ := h.ids.OrgByID(h.ctx, org.ID)
	if !o.SSOEnforced || !o.JITEnabled || o.DefaultRole != identity.RoleDeveloper || o.Name != "Acme Pty Ltd" {
		t.Fatalf("settings: %+v", o)
	}
	if r := ob.post("/console/orgs/acme/settings", url.Values{"name": {"x"}, "default_role": {"owner"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("owner default role: %d", r.Status)
	}
	if o, _ := h.ids.OrgByID(h.ctx, org.ID); o.DefaultRole != identity.RoleDeveloper {
		t.Fatal("default role set to owner")
	}

	// Delete.
	k := h.issue(org, owner, "live")
	if r := admin.post("/console/orgs/acme/settings/delete", url.Values{"confirm": {"acme"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("admin delete: %d", r.Status)
	}
	if r := ob.post("/console/orgs/acme/settings/delete", url.Values{"confirm": {"acm"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("wrong confirm: %d", r.Status)
	}
	if _, err := h.ids.OrgByID(h.ctx, org.ID); err != nil {
		t.Fatal("deleted without confirmation")
	}
	if r := ob.post("/console/orgs/acme/settings/delete", url.Values{"confirm": {"acme"}}, true); r.Status != http.StatusSeeOther || r.Location != "/console" {
		t.Fatalf("delete: %d %s", r.Status, r.Location)
	}
	if _, err := h.ids.OrgByID(h.ctx, org.ID); err == nil {
		t.Fatal("org not deleted")
	}
	if k, _ := h.keys.OrgKey(org.ID, k.ID); k.Revoked == nil {
		t.Fatal("key not revoked")
	}
	if !h.hasAudit(org, "org.delete") || !h.hasAudit(org, "org.settings") {
		t.Fatal("missing audit")
	}
}

func mustInviteID(t *testing.T, h *harness, orgID int64, email string) int64 {
	t.Helper()
	inv, _ := h.ids.Invites(h.ctx, orgID)
	for _, i := range inv {
		if i.Email == email {
			return i.ID
		}
	}
	t.Fatalf("no invite for %s", email)
	return 0
}
