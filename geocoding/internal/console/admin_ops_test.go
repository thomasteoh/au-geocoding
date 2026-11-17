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
	"time"

	"augeocoding/internal/identity"
	"augeocoding/internal/outbox"
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
	var logs bytes.Buffer
	h.con.Log = slog.New(&logs, slog.LevelDebug, nil)
	worker := outbox.New(h.ids, fm, h.con.Log)
	worker.Backoff = []time.Duration{0}
	woken := 0
	h.con.MailOn, h.con.MailWake = true, func() { woken++ }
	b := h.signIn(owner)

	// The handler only queues; nothing is sent on the request path.
	r := b.post("/console/orgs/acme/invites", url.Values{"email": {"new@example.com"}, "role": {"developer"}}, true)
	if !strings.Contains(b.flash(r), "We are emailing them") || woken != 1 {
		t.Fatalf("no queued flash / wake (%d)", woken)
	}
	if len(fm.sent) != 0 {
		t.Fatal("sent on the request path")
	}
	worker.RunOnce(h.ctx)
	if len(fm.sent) != 1 {
		t.Fatalf("sent: %+v", fm.sent)
	}
	m := fm.sent[0]
	if m.to != "new@example.com" || strings.ContainsAny(m.subject, "\r\n") || !strings.Contains(m.subject, `"Acme Bcc: eve@example com"`) {
		t.Fatalf("subject/to: %+v", m)
	}
	for _, want := range []string{`"Olive Owner" (owner@acme.example)`, "as developer", h.srv.URL + "/auth/login", "expires on"} {
		if !strings.Contains(m.body, want) {
			t.Errorf("body lacks %q:\n%s", want, m.body)
		}
	}

	// A failing server: the invite stands, the worker retries then gives
	// up, and nothing logged carries the address.
	fm.err = errors.New("550 5.1.1 <second@example.com>: mailbox unavailable")
	b.post("/console/orgs/acme/invites", url.Values{"email": {"second@example.com"}, "role": {"viewer"}}, true)
	worker.RunOnce(h.ctx)
	if inv, _ := h.ids.Invites(h.ctx, mustOrg(h, "acme").ID); len(inv) != 2 {
		t.Fatalf("invite lost on mail failure: %+v", inv)
	}
	st, _ := h.ids.MailStatuses(h.ctx)
	if len(st) != 2 || st[1].Status != identity.MailFailed || st[1].Attempts != 2 || st[1].HasBody || st[1].HasRcpt {
		t.Fatalf("outbox: %+v", st)
	}
	if !strings.Contains(logs.String(), "mail_failed") || strings.Contains(logs.String(), "second@example.com") {
		t.Fatalf("log: %s", logs.String())
	}
	fm.err = nil

	// Per-recipient limit: re-inviting the same address a fourth time in a
	// day still updates the invite but queues no email.
	for i := 0; i < 2; i++ {
		r = b.post("/console/orgs/acme/invites", url.Values{"email": {"new@example.com"}, "role": {"developer"}}, true)
		if !strings.Contains(b.flash(r), "We are emailing them") {
			t.Fatalf("re-invite %d not queued", i)
		}
	}
	r = b.post("/console/orgs/acme/invites", url.Values{"email": {"new@example.com"}, "role": {"admin"}}, true)
	if f := b.flash(r); !strings.Contains(f, "No email was sent") || !strings.Contains(f, "Invited new@example.com") {
		t.Fatalf("limit flash: %q", f)
	}
	if st, _ := h.ids.MailStatuses(h.ctx); len(st) != 4 {
		t.Fatalf("queued over the limit: %d rows", len(st))
	}
	inv, _ := h.ids.Invites(h.ctx, mustOrg(h, "acme").ID)
	for _, i := range inv {
		if i.Email == "new@example.com" && i.Role != identity.RoleAdmin {
			t.Fatal("invite not updated when the email was limited")
		}
	}

	// No mail configured: the flash says nothing about email.
	h.con.MailOn = false
	r = b.post("/console/orgs/acme/invites", url.Values{"email": {"third@example.com"}, "role": {"viewer"}}, true)
	if body := b.flash(r); strings.Contains(body, "emailing") || strings.Contains(body, "No email was sent") || strings.Contains(body, "could not be sent") {
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
