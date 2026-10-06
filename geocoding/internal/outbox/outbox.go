// Package outbox delivers queued email (identity.Store's mail_outbox) off
// the request path. Handlers enqueue and return; Worker.Run sends due
// messages, retrying with backoff, and marks each sent or failed. The
// worker logs outbox IDs, org IDs and address-free error codes, never
// recipients.
package outbox

import (
	"context"
	"time"

	"augeocoding/internal/identity"
	"augeocoding/internal/mail"
	"ausystem/shared/slog"
)

// Backoff is the wait after each failed attempt. A message gets
// len(Backoff)+1 attempts, then is marked failed.
var Backoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 2 * time.Hour}

// Worker sends queued mail. Run it once per process.
type Worker struct {
	Store    *identity.Store
	Sender   mail.Sender
	Log      *slog.Logger
	Interval time.Duration // poll interval; default 30s
	Backoff  []time.Duration

	wake chan struct{}
}

// New returns a worker.
func New(store *identity.Store, sender mail.Sender, log *slog.Logger) *Worker {
	return &Worker{Store: store, Sender: sender, Log: log, Interval: 30 * time.Second, Backoff: Backoff, wake: make(chan struct{}, 1)}
}

// Wake asks the worker to look at the queue now (after an enqueue). It
// never blocks.
func (w *Worker) Wake() {
	if w == nil || w.wake == nil {
		return
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Run delivers due mail until ctx ends. A send in progress when ctx ends is
// abandoned and left pending, not counted as an attempt.
func (w *Worker) Run(ctx context.Context) {
	if w.wake == nil {
		w.wake = make(chan struct{}, 1)
	}
	iv := w.Interval
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		w.RunOnce(ctx)
		if time.Since(lastPrune) > time.Hour {
			if err := w.Store.PruneMail(ctx); err != nil && ctx.Err() == nil {
				w.Log.Error("mail_outbox_prune_failed", "error", err.Error())
			}
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.wake:
		}
	}
}

// RunOnce sends every message due now, in batches.
func (w *Worker) RunOnce(ctx context.Context) {
	for ctx.Err() == nil {
		due, err := w.Store.DueMail(ctx, 20)
		if err != nil {
			if ctx.Err() == nil {
				w.Log.Error("mail_outbox_read_failed", "error", err.Error())
			}
			return
		}
		if len(due) == 0 {
			return
		}
		progressed := false
		for _, m := range due {
			if ctx.Err() != nil {
				return
			}
			if w.deliver(ctx, m) {
				progressed = true
			}
		}
		if !progressed {
			return
		}
	}
}

// deliver sends one message and records the outcome. It reports whether the
// row left the due set.
func (w *Worker) deliver(ctx context.Context, m identity.QueuedMail) bool {
	sctx, cancel := context.WithTimeout(ctx, mail.Timeout)
	err := w.Sender.Send(sctx, m.To, m.Subject, m.Body)
	cancel()
	if err != nil && ctx.Err() != nil {
		return false // shutting down: try again next start
	}
	// Recording uses a fresh context so a shutdown racing the send cannot
	// leave a delivered message pending (and sent twice).
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer rcancel()
	attempt := m.Attempts + 1
	if err == nil {
		if err := w.Store.MarkMailSent(rctx, m.ID); err != nil {
			w.Log.Error("mail_outbox_write_failed", "outbox_id", m.ID, "error", err.Error())
			return false
		}
		w.Log.Info("mail_sent", "outbox_id", m.ID, "org_id", m.OrgID, "kind", m.Kind, "attempt", attempt)
		return true
	}
	code := mail.ErrorCode(err)
	backoff := w.Backoff
	if backoff == nil {
		backoff = Backoff
	}
	if mail.Permanent(err) || attempt > len(backoff) {
		if err := w.Store.MarkMailFailed(rctx, m.ID, code); err != nil {
			w.Log.Error("mail_outbox_write_failed", "outbox_id", m.ID, "error", err.Error())
			return false
		}
		w.Log.Warn("mail_failed", "outbox_id", m.ID, "org_id", m.OrgID, "kind", m.Kind, "attempt", attempt, "code", code)
		return true
	}
	next := time.Now().Add(backoff[attempt-1])
	if err := w.Store.MarkMailRetry(rctx, m.ID, code, next); err != nil {
		w.Log.Error("mail_outbox_write_failed", "outbox_id", m.ID, "error", err.Error())
		return false
	}
	w.Log.Warn("mail_retry", "outbox_id", m.ID, "org_id", m.OrgID, "kind", m.Kind, "attempt", attempt, "code", code, "next_in", backoff[attempt-1].String())
	return true
}
