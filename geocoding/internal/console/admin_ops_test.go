package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
	"ausystem/shared/slog"
)

// fakeMail records sends and fails when err is set.
type fakeMail struct {
	mu   sync.Mutex
	err  error
	sent []sentMail
}

type sentMail struct{ to, subject, body string }

func (f *fakeMail) Send(_ context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentMail{to, subject, body})
	return nil
}

func TestInviteEmail(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	h.ids.SetUserName(h.ctx, owner.ID, "Olive Owner")
	h.org("acme", owner)
	h.ids.UpdateOrgSettings(h.ctx, mustOrg(h, "acme").ID, identity.OrgSettings{Name: "Acme\r\nBcc: eve@example.com", DefaultRole: identity.RoleViewer})
	fm := &fakeMail{}
	h.con.Mail = fm
	var logs bytes.Buffer
	h.con.Log = slog.New(&logs, slog.LevelDebug, nil)
	b := h.signIn(owner)

	r := b.post("/console/orgs/acme/invites", url.Values{"email": {"new@example.com"}, "role": {"developer"}}, true)
	if !strings.Contains(b.flash(r), "We emailed them") {
		t.Fatal("no sent flash")
	}
	if len(fm.sent) != 1 {
		t.Fatalf("sent: %+v", fm.sent)
	}
	m := fm.sent[0]
	if m.to != "new@example.com" || strings.ContainsAny(m.subject, "\r\n") || !strings.Contains(m.subject, "Acme Bcc: eve@example.com") {
		t.Fatalf("subject/to: %+v", m)
	}
	for _, want := range []string{"Olive Owner (owner@acme.example)", "as developer", h.srv.URL + "/auth/login", "expires on"} {
		if !strings.Contains(m.body, want) {
			t.Errorf("body lacks %q:\n%s", want, m.body)
		}
	}

	// A failed send keeps the invite, says so, and logs without the address.
	fm.err = errors.New("550 5.1.1 <second@example.com>: mailbox unavailable")
	r = b.post("/console/orgs/acme/invites", url.Values{"email": {"second@example.com"}, "role": {"viewer"}}, true)
	if !strings.Contains(b.flash(r), "could not be sent") {
		t.Fatal("no failure flash")
	}
	if inv, _ := h.ids.Invites(h.ctx, mustOrg(h, "acme").ID); len(inv) != 2 {
		t.Fatalf("invite lost on mail failure: %+v", inv)
	}
	if !strings.Contains(logs.String(), "invite_email_failed") || strings.Contains(logs.String(), "second@example.com") {
		t.Fatalf("log: %s", logs.String())
	}

	// No mail configured: the flash says nothing about email.
	h.con.Mail = nil
	r = b.post("/console/orgs/acme/invites", url.Values{"email": {"third@example.com"}, "role": {"viewer"}}, true)
	if body := b.flash(r); strings.Contains(body, "emailed") || strings.Contains(body, "could not be sent") {
		t.Fatal("mail flash without mail")
	}
}

func mustOrg(h *harness, slug string) identity.Org {
	h.t.Helper()
	o, err := h.ids.OrgBySlug(h.ctx, slug)
	if err != nil {
		h.t.Fatal(err)
	}
	return o
}

func TestAuditMarksPlatformAdmin(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	_, admin := h.platformAdmin("root@example.com")
	if r := admin.post("/console/orgs/acme/invites", url.Values{"email": {"x@example.com"}, "role": {"viewer"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("invite as platform admin: %d", r.Status)
	}
	if e := h.latestAudit(org.ID); e.Action != "invite.create" || e.Detail != "[platform-admin] role=viewer" {
		t.Fatalf("platform admin event: %+v", e)
	}
	ob := h.signIn(owner)
	ob.post("/console/orgs/acme/invites", url.Values{"email": {"y@example.com"}, "role": {"viewer"}}, true)
	if e := h.latestAudit(org.ID); e.Detail != "role=viewer" {
		t.Fatalf("member event: %+v", e)
	}
}

var linkRe = regexp.MustCompile(`href="(/console/admin/users\?[^"]*)">(Older|Newer) users`)

func pageLinks(body string) map[string]string {
	out := map[string]string{}
	for _, m := range linkRe.FindAllStringSubmatch(body, -1) {
		out[m[2]] = strings.ReplaceAll(m[1], "&amp;", "&")
	}
	return out
}

func TestAdminUsersPaging(t *testing.T) {
	h := newHarness(t, open)
	_, b := h.platformAdmin("root@example.com")
	for i := 0; i < 150; i++ {
		h.user(fmt.Sprintf("p%03d@paged.example", i))
	}
	h.user("someone@else.example")

	r := b.get("/console/admin/users?q=paged.example")
	links := pageLinks(r.Body)
	if !strings.Contains(r.Body, "p149@paged.example") || !strings.Contains(r.Body, "p050@paged.example") ||
		strings.Contains(r.Body, "p049@paged.example") || strings.Contains(r.Body, "someone@else") {
		t.Fatal("first page contents")
	}
	if links["Newer"] != "" || !strings.Contains(links["Older"], "q=paged.example") {
		t.Fatalf("first page links: %v", links)
	}
	r = b.get(links["Older"])
	older := pageLinks(r.Body)
	if !strings.Contains(r.Body, "p049@paged.example") || !strings.Contains(r.Body, "p000@paged.example") || strings.Contains(r.Body, "p050@paged.example") {
		t.Fatal("second page contents")
	}
	if older["Older"] != "" || !strings.Contains(older["Newer"], "q=paged.example") {
		t.Fatalf("second page links: %v", older)
	}
	// Actions return to the page and search they came from.
	victim := h.mustUser("p010@paged.example")
	rr := b.post(fmt.Sprintf("/console/admin/users/%d/status", victim.ID),
		url.Values{"status": {"suspended"}, "q": {"paged.example"}, "before": {"12345"}}, true)
	if rr.Location != "/console/admin/users?before=12345&q=paged.example" {
		t.Fatalf("back: %s", rr.Location)
	}
	r = b.get(older["Newer"])
	if !strings.Contains(r.Body, "p149@paged.example") || !strings.Contains(r.Body, "p050@paged.example") || strings.Contains(r.Body, "p049@paged.example") {
		t.Fatal("newer page contents")
	}
	if l := pageLinks(r.Body); l["Newer"] != "" || l["Older"] == "" {
		t.Fatalf("newer page links: %v", l)
	}
}

// The org's tier and its keys' tier change together, including the
// in-memory index used by authentication.
func TestAdminOrgTierUpdatesLiveKeys(t *testing.T) {
	h := newHarness(t, open)
	owner := h.user("owner@acme.example")
	org := h.org("acme", owner)
	_, raw, err := h.keys.IssueKeyWith(publicapi.IssueOptions{Label: "k", Tier: publicapi.QuotaTier(org.Tier), OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	_, b := h.platformAdmin("root@example.com")
	b.post(fmt.Sprintf("/console/admin/orgs/%d/tier", org.ID), url.Values{"tier": {"batch"}}, true)
	if k, _ := h.keys.Authenticate(raw); k.Tier != publicapi.TierBatch {
		t.Fatalf("live key tier: %v", k.Tier)
	}
	// An invalid tier changes neither.
	b.post(fmt.Sprintf("/console/admin/orgs/%d/tier", org.ID), url.Values{"tier": {"anonymous"}}, true)
	if o, _ := h.ids.OrgByID(h.ctx, org.ID); o.Tier != "batch" {
		t.Fatalf("org tier: %s", o.Tier)
	}
	if k, _ := h.keys.Authenticate(raw); k.Tier != publicapi.TierBatch {
		t.Fatalf("live key tier after invalid: %v", k.Tier)
	}
}

// The last active platform admin cannot be demoted or suspended; a suspended
// admin is not counted and can still be demoted.
func TestAdminLastAdminProtected(t *testing.T) {
	h := newHarness(t, open)
	root, b := h.platformAdmin("root@example.com")
	second := h.user("second@example.com")
	h.ids.SetPlatformAdmin(h.ctx, second.ID, true)
	if r := b.post(fmt.Sprintf("/console/admin/users/%d/status", second.ID), url.Values{"status": {"suspended"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("suspend second: %d", r.Status)
	}
	if err := h.ids.RevokePlatformAdmin(h.ctx, root.ID); !errors.Is(err, identity.ErrLastPlatformAdmin) {
		t.Fatalf("revoke last: %v", err)
	}
	if r := b.post(fmt.Sprintf("/console/admin/users/%d/admin", second.ID), url.Values{"admin": {"0"}}, true); r.Status != http.StatusSeeOther {
		t.Fatalf("demote suspended: %d", r.Status)
	}
	if u, _ := h.ids.UserByID(h.ctx, second.ID); u.PlatformAdmin {
		t.Fatal("suspended admin not demoted")
	}
}
