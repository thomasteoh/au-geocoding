package console

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
)

// An invite never takes effect at sign-in: the recipient sees it on the
// console home page and accepts or declines it with a CSRF-checked POST.
func TestInviteExplicitAccept(t *testing.T) {
	h := newHarness(t, open)
	eve := h.user("eve@evil.example")
	evil := h.org("evil", eve)
	other := h.org("other", eve)
	h.ids.CreateInvite(h.ctx, evil.ID, "victim@corp.example", identity.RoleOwner, eve.ID, inviteTTL)
	h.ids.CreateInvite(h.ctx, other.ID, "victim@corp.example", identity.RoleViewer, eve.ID, inviteTTL)
	victim, _ := h.ids.CreateUser(h.ctx, "victim@corp.example", "")
	b := h.signIn(victim)
	if r, _ := h.ids.Role(h.ctx, evil.ID, victim.ID); r != identity.RoleNone {
		t.Fatalf("sign-in joined the inviting org as %v", r)
	}
	home := b.get("/console")
	if home.Status != http.StatusOK || !strings.Contains(home.Body, "Invitations") || !strings.Contains(home.Body, "eve@evil.example") {
		t.Fatalf("home: %d %s", home.Status, home.Body)
	}
	inv, _ := h.ids.UserInvites(h.ctx, victim)
	var evilID, otherID int64
	for _, i := range inv {
		if i.OrgID == evil.ID {
			evilID = i.ID
		} else {
			otherID = i.ID
		}
	}
	// No CSRF token: refused, nothing joined.
	if r := b.post(fmt.Sprintf("/console/invites/%d/accept", evilID), nil, false); r.Status != http.StatusForbidden {
		t.Fatalf("accept without csrf: %d", r.Status)
	}
	// Someone else cannot accept the victim's invite.
	if r := h.signIn(eve).post(fmt.Sprintf("/console/invites/%d/accept", evilID), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("foreign accept: %d", r.Status)
	}
	if r, _ := h.ids.Role(h.ctx, evil.ID, victim.ID); r != identity.RoleNone {
		t.Fatal("joined without the recipient accepting")
	}
	if f := b.flash(b.post(fmt.Sprintf("/console/invites/%d/decline", evilID), nil, true)); !strings.Contains(f, "declined") {
		t.Fatalf("decline flash: %s", f)
	}
	r := b.post(fmt.Sprintf("/console/invites/%d/accept", otherID), nil, true)
	if r.Status != http.StatusSeeOther || r.Location != "/console/orgs/other" {
		t.Fatalf("accept: %d %s", r.Status, r.Location)
	}
	if role, _ := h.ids.Role(h.ctx, other.ID, victim.ID); role != identity.RoleViewer {
		t.Fatalf("role after accept: %v", role)
	}
	if role, _ := h.ids.Role(h.ctx, evil.ID, victim.ID); role != identity.RoleNone {
		t.Fatal("declined invite took effect")
	}
	if !h.hasAudit(other, "invite.accept") || !h.hasAudit(evil, "invite.decline") {
		t.Fatal("missing invite audit")
	}
}

// Admins cannot delete or downgrade an owner invite (canManage), owners can.
func TestOwnerInviteNeedsOwner(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	admin, _ := h.member("admin@acme.example", org, identity.RoleAdmin)
	h.ids.CreateInvite(h.ctx, org.ID, "boss@example.com", identity.RoleOwner, owner.ID, inviteTTL)
	id := mustInviteID(t, h, org.ID, "boss@example.com")
	if r := admin.post(fmt.Sprintf("/console/orgs/acme/invites/%d/delete", id), nil, true); r.Status != http.StatusForbidden {
		t.Fatalf("admin deleted owner invite: %d", r.Status)
	}
	if r := admin.post("/console/orgs/acme/invites", url.Values{"email": {"boss@example.com"}, "role": {"viewer"}}, true); r.Status != http.StatusForbidden {
		t.Fatalf("admin downgraded owner invite: %d", r.Status)
	}
	inv, _ := h.ids.Invites(h.ctx, org.ID)
	if len(inv) != 1 || inv[0].Role != identity.RoleOwner {
		t.Fatalf("owner invite changed: %+v", inv)
	}
	if page := admin.get("/console/orgs/acme/members"); strings.Contains(page.Body, fmt.Sprintf("/invites/%d/delete", id)) {
		t.Fatal("admin offered a delete button for an owner invite")
	}
	ob := h.signIn(owner)
	if r := ob.post(fmt.Sprintf("/console/orgs/acme/invites/%d/delete", id), nil, true); r.Status != http.StatusSeeOther {
		t.Fatalf("owner delete: %d", r.Status)
	}
}

func TestOrgCreationCap(t *testing.T) {
	h := newHarness(t, open)
	h.con.Cfg.MaxOrgsPerUser = 1
	u := h.user("u@example.com")
	b := h.signIn(u)
	if r := b.post("/console/orgs", url.Values{"name": {"First"}}, true); r.Status != http.StatusSeeOther || r.Location != "/console/orgs/first" {
		t.Fatalf("first: %d %s", r.Status, r.Location)
	}
	if f := b.flash(b.post("/console/orgs", url.Values{"name": {"Second"}}, true)); !strings.Contains(f, "up to 1 organisations") {
		t.Fatalf("over cap: %s", f)
	}
	if _, err := h.ids.OrgBySlug(h.ctx, "second"); !errors.Is(err, identity.ErrNotFound) {
		t.Fatal("second org created over the cap")
	}
}

// A key issued while its org is being deleted never survives the delete:
// the delete revokes keys in its own transaction and the issue checks the
// org inside its transaction.
func TestOrgDeleteRevokesConcurrentKeys(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	var mu sync.Mutex
	var raws []string
	issue := func() error {
		_, raw, err := h.keys.IssueKeyWith(publicapi.IssueOptions{Label: "k", Tier: publicapi.TierDemo, Scopes: []string{"search"}, OrgID: org.ID,
			Guard: func(tx *sql.Tx) error { return identity.OrgExistsTx(h.ctx, tx, org.ID) }})
		if err == nil {
			mu.Lock()
			raws = append(raws, raw)
			mu.Unlock()
		}
		return err
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if err := issue(); err != nil && !errors.Is(err, identity.ErrNotFound) {
					t.Error(err)
				}
			}
		}()
	}
	if err := h.ids.DeleteOrgWith(h.ctx, org.ID, func(tx *sql.Tx) error { return h.keys.RevokeOrgKeysTx(tx, org.ID) }); err != nil {
		t.Fatal(err)
	}
	h.keys.ForgetOrgKeys(org.ID)
	wg.Wait()
	if err := issue(); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("key issued for a deleted org: %v", err)
	}
	keys, _ := h.keys.OrgKeys(org.ID)
	for _, k := range keys {
		if k.Revoked == nil {
			t.Fatalf("key %d survived the org delete", k.ID)
		}
	}
	for _, raw := range raws {
		if _, err := h.keys.Authenticate(raw); err == nil {
			t.Fatal("key of a deleted org still authenticates")
		}
	}
}

func TestTokensPageWarnsSharedIssuer(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	squat := h.org("squat", h.user("x@squat.example"))
	for _, o := range []identity.Org{org, squat} {
		if _, err := h.ids.SaveJWTIssuer(h.ctx, identity.JWTIssuer{OrgID: o.ID, Issuer: "https://login.example/t", Audience: "api://geo", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	page := h.signIn(owner).get("/console/orgs/acme/tokens")
	if !strings.Contains(page.Body, "Another organisation has registered the same issuer and audience") || strings.Contains(page.Body, "squat") {
		t.Fatalf("tokens page: %s", page.Body)
	}
}

func TestMailName(t *testing.T) {
	for in, want := range map[string]string{
		"Acme Pty Ltd":                     "Acme Pty Ltd",
		"Visit https://evil.example/login": "Visit evil example/login",
		"www.evil.example":                 "evil example",
		"login.evil.example now":           "login evil example now",
		`Say "hi"`:                         "Say 'hi'",
		"Acme\r\nBcc: eve@example.com":     "Acme Bcc: eve@example com",
		"hxxp://x.y and FTP://a.b":         "x y and a b",
		"evil。example (ideographic dot)":   "evil example (ideographic dot)",
	} {
		if got := mailName(in); got != want {
			t.Errorf("mailName(%q) = %q, want %q", in, got, want)
		}
	}
}
