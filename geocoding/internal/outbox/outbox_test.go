package outbox

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"augeocoding/internal/appdb"
	"augeocoding/internal/identity"
	"augeocoding/internal/mail"
	"ausystem/shared/slog"
)

type fakeSender struct {
	mu    sync.Mutex
	errs  []error // returned in order; nil entries succeed; past the end: success
	calls int
	sent  []string
	block chan struct{} // non-nil: wait for ctx end
}

func (f *fakeSender) Send(ctx context.Context, to, subject, body string) error {
	f.mu.Lock()
	i := f.calls
	f.calls++
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-ctx.Done()
		return ctx.Err()
	}
	if i < len(f.errs) && f.errs[i] != nil {
		return f.errs[i]
	}
	f.mu.Lock()
	f.sent = append(f.sent, to)
	f.mu.Unlock()
	return nil
}

func setup(t *testing.T) (*identity.Store, int64, *bytes.Buffer, *slog.Logger) {
	t.Helper()
	db, err := appdb.Open(t.TempDir() + "/app.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ids, err := identity.New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u, _ := ids.CreateUser(ctx, "owner@acme.example", "")
	org, err := ids.CreateOrg(ctx, "Acme", "acme", u.ID, false, false)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return ids, org.ID, &logs, slog.New(&logs, slog.LevelDebug, nil)
}

func TestWorkerRetriesThenSends(t *testing.T) {
	ids, org, logs, log := setup(t)
	ctx := context.Background()
	ids.EnqueueInviteMail(ctx, org, "ada@example.com", "hi", "body")
	tempErr := &mail.SendError{Stage: "dial", Err: errors.New("connection refused to ada@example.com")}
	fs := &fakeSender{errs: []error{tempErr, tempErr}}
	w := New(ids, fs, log)
	w.Backoff = []time.Duration{0, 0, 0, 0, 0}

	w.RunOnce(ctx)
	st, _ := ids.MailStatuses(ctx)
	if len(st) != 1 || st[0].Status != identity.MailSent || st[0].Attempts != 3 || st[0].HasBody || st[0].HasRcpt {
		t.Fatalf("status %+v", st)
	}
	if len(fs.sent) != 1 || fs.sent[0] != "ada@example.com" {
		t.Fatalf("sent %v", fs.sent)
	}
	if strings.Contains(logs.String(), "ada@example.com") || !strings.Contains(logs.String(), `"code":"dial"`) {
		t.Fatalf("logs: %s", logs.String())
	}
}

func TestWorkerBackoffAndFinalFailure(t *testing.T) {
	ids, org, _, log := setup(t)
	ctx := context.Background()
	ids.EnqueueInviteMail(ctx, org, "ada@example.com", "hi", "body")
	tempErr := &mail.SendError{Stage: "dial", Err: errors.New("refused")}
	fs := &fakeSender{errs: []error{tempErr, tempErr, tempErr, tempErr, tempErr, tempErr, tempErr}}
	w := New(ids, fs, log)

	// Default backoff: after one failure the message waits a minute.
	w.RunOnce(ctx)
	if fs.calls != 1 {
		t.Fatalf("calls %d", fs.calls)
	}
	w.RunOnce(ctx)
	if fs.calls != 1 {
		t.Fatal("retried before the backoff elapsed")
	}

	// With no wait, it is tried len(Backoff)+1 = 6 times, then failed.
	ids2, org2, _, _ := setup(t)
	ids2.EnqueueInviteMail(ctx, org2, "bob@example.com", "hi", "body")
	fs.calls = 0
	w2 := New(ids2, fs, log)
	w2.Backoff = make([]time.Duration, len(Backoff))
	w2.RunOnce(ctx)
	st, _ := ids2.MailStatuses(ctx)
	if fs.calls != 6 || len(st) != 1 || st[0].Status != identity.MailFailed || st[0].Attempts != 6 || st[0].HasBody || st[0].HasRcpt || st[0].LastError != "dial" {
		t.Fatalf("calls=%d status %+v", fs.calls, st)
	}
}

func TestWorkerPermanentFailure(t *testing.T) {
	ids, org, _, log := setup(t)
	ctx := context.Background()
	ids.EnqueueInviteMail(ctx, org, "ada@example.com", "hi", "body")
	fs := &fakeSender{errs: []error{mail.ErrInvalid}}
	New(ids, fs, log).RunOnce(ctx)
	st, _ := ids.MailStatuses(ctx)
	if fs.calls != 1 || st[0].Status != identity.MailFailed || st[0].LastError != "invalid" || st[0].HasBody {
		t.Fatalf("calls=%d %+v", fs.calls, st)
	}
}

// Run stops when its context ends; a send cut off by shutdown stays
// pending without using up an attempt.
func TestWorkerShutdown(t *testing.T) {
	ids, org, _, log := setup(t)
	ids.EnqueueInviteMail(context.Background(), org, "ada@example.com", "hi", "body")
	fs := &fakeSender{block: make(chan struct{})}
	w := New(ids, fs, log)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fs.mu.Lock()
		c := fs.calls
		fs.mu.Unlock()
		if c > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker never sent")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	st, _ := ids.MailStatuses(context.Background())
	if st[0].Status != identity.MailPending || st[0].Attempts != 0 || !st[0].HasBody {
		t.Fatalf("%+v", st)
	}
}

// Wake makes a running worker send a newly queued message without waiting
// for the poll interval.
func TestWorkerWake(t *testing.T) {
	ids, org, _, log := setup(t)
	fs := &fakeSender{}
	w := New(ids, fs, log)
	w.Interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	time.Sleep(20 * time.Millisecond)
	ids.EnqueueInviteMail(ctx, org, "ada@example.com", "hi", "body")
	w.Wake()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fs.mu.Lock()
		n := len(fs.sent)
		fs.mu.Unlock()
		if n == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("wake did not deliver")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
