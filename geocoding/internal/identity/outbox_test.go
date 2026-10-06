package identity

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestMailOutboxRateLimits(t *testing.T) {
	s := newStore(t)
	owner, _ := s.CreateUser(ctx, "owner@acme.example", "")
	org, err := s.CreateOrg(ctx, "Acme", "acme", owner.ID, false, false)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.CreateOrg(ctx, "Beta", "beta", owner.ID, false, false)

	// Per recipient per org, case-insensitively: one org cannot use up
	// another org's allowance for the same address.
	for i := 0; i < MailRecipientPerDay; i++ {
		if err := s.EnqueueInviteMail(ctx, org.ID, "Ada@example.com", "s", "b"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := s.EnqueueInviteMail(ctx, org.ID, "ada@example.com", "s", "b"); !errors.Is(err, ErrMailRateLimited) {
		t.Fatalf("4th from one org: %v", err)
	}
	if err := s.EnqueueInviteMail(ctx, other.ID, "ada@example.com", "s", "b"); err != nil {
		t.Fatalf("other org blocked by first org's sends: %v", err)
	}
	// Finishing a message does not reset the count.
	due, _ := s.DueMail(ctx, 10)
	for _, m := range due {
		s.MarkMailSent(ctx, m.ID)
	}
	if err := s.EnqueueInviteMail(ctx, org.ID, "ada@example.com", "s", "b"); !errors.Is(err, ErrMailRateLimited) {
		t.Fatalf("after send: %v", err)
	}

	// Per org per hour: org already queued 3.
	for i := 3; i < MailOrgPerHour; i++ {
		if err := s.EnqueueInviteMail(ctx, org.ID, fmt.Sprintf("u%d@example.com", i), "s", "b"); err != nil {
			t.Fatalf("org send %d: %v", i, err)
		}
	}
	if err := s.EnqueueInviteMail(ctx, org.ID, "late@example.com", "s", "b"); !errors.Is(err, ErrMailRateLimited) {
		t.Fatalf("org limit: %v", err)
	}
	if err := s.EnqueueInviteMail(ctx, other.ID, "late@example.com", "s", "b"); err != nil {
		t.Fatalf("other org blocked: %v", err)
	}

	// An hour later the org may send again.
	old := clock
	t.Cleanup(func() { clock = old })
	clock = func() time.Time { return old().Add(61 * time.Minute) }
	if err := s.EnqueueInviteMail(ctx, org.ID, "later@example.com", "s", "b"); err != nil {
		t.Fatalf("after an hour: %v", err)
	}
}

func TestMailOutboxLifecycle(t *testing.T) {
	s := newStore(t)
	owner, _ := s.CreateUser(ctx, "owner@acme.example", "")
	org, _ := s.CreateOrg(ctx, "Acme", "acme", owner.ID, false, false)
	for _, to := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if err := s.EnqueueInviteMail(ctx, org.ID, to, "subj", "body "+to); err != nil {
			t.Fatal(err)
		}
	}
	due, err := s.DueMail(ctx, 10)
	if err != nil || len(due) != 3 || due[0].To != "a@example.com" || due[0].Body != "body a@example.com" || due[0].Kind != "invite" {
		t.Fatalf("due: %v %+v", err, due)
	}
	s.MarkMailSent(ctx, due[0].ID)
	s.MarkMailRetry(ctx, due[1].ID, "dial", time.Now().Add(time.Hour))
	s.MarkMailFailed(ctx, due[2].ID, "rcpt_550")
	// Marking a finished row again changes nothing.
	s.MarkMailRetry(ctx, due[0].ID, "dial", time.Now())
	if again, _ := s.DueMail(ctx, 10); len(again) != 0 {
		t.Fatalf("not due yet / finished rows came back: %+v", again)
	}
	st, _ := s.MailStatuses(ctx)
	want := []MailStatus{
		{ID: due[0].ID, Status: MailSent, Attempts: 1},
		{ID: due[1].ID, Status: MailPending, Attempts: 1, LastError: "dial", HasBody: true, HasRcpt: true},
		{ID: due[2].ID, Status: MailFailed, Attempts: 1, LastError: "rcpt_550"},
	}
	for i := range want {
		if st[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, st[i], want[i])
		}
	}
	// Finished rows are pruned after the retention window; pending stay.
	old := clock
	t.Cleanup(func() { clock = old })
	clock = func() time.Time { return old().Add(MailRetention + time.Hour) }
	if err := s.PruneMail(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.MailStatuses(ctx); len(st) != 1 || st[0].ID != due[1].ID {
		t.Fatalf("after prune: %+v", st)
	}
}

func TestStartFlowCap(t *testing.T) {
	s := newStore(t)
	old := MaxFlows
	t.Cleanup(func() { MaxFlows = old })
	MaxFlows = 3
	for i := 0; i < 3; i++ {
		if _, _, err := s.StartFlow(ctx, Flow{Kind: "oidc"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.StartFlow(ctx, Flow{Kind: "oidc"}); !errors.Is(err, ErrTooManyFlows) {
		t.Fatalf("want ErrTooManyFlows, got %v", err)
	}
	// Expired flows do not count.
	oldClock := clock
	t.Cleanup(func() { clock = oldClock })
	clock = func() time.Time { return oldClock().Add(FlowTTL + time.Minute) }
	if _, _, err := s.StartFlow(ctx, Flow{Kind: "oidc"}); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestMailRecipientGlobalLimit(t *testing.T) {
	s := newStore(t)
	owner, _ := s.CreateUser(ctx, "owner@acme.example", "")
	sent := 0
	for i := 0; sent < MailRecipientGlobalPerDay+5; i++ {
		o, err := s.CreateOrg(ctx, fmt.Sprintf("Org %d", i), "", owner.ID, false, true)
		if err != nil {
			t.Fatal(err)
		}
		err = s.EnqueueInviteMail(ctx, o.ID, "victim@example.com", "s", "b")
		if errors.Is(err, ErrMailRateLimited) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		sent++
	}
	if sent != MailRecipientGlobalPerDay {
		t.Fatalf("global cap: %d sent", sent)
	}
}
