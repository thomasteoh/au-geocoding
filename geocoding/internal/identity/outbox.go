package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

// Mail outbox (docs/auth.md "Invite emails"). Handlers enqueue; a background
// worker (package outbox) sends with retries. Recipient and body are cleared
// when a message reaches a final state, so app.db does not keep mail
// content; the row and a hash of the recipient stay for MailRetention to
// enforce the rate limits.

// Invite mail rate limits. Over either limit EnqueueInviteMail returns
// ErrMailRateLimited and queues nothing.
var (
	MailOrgPerHour = 50 // invite emails one org may queue per hour
	// MailRecipientPerDay bounds emails from one org to one address, so one
	// org cannot use up another org's allowance for that address.
	MailRecipientPerDay = 3
	// MailRecipientGlobalPerDay bounds emails to one address from all orgs
	// together, so many throwaway orgs cannot flood a mailbox.
	MailRecipientGlobalPerDay = 20
)

// MailRetention is how long finished outbox rows (without recipient or body)
// are kept for rate limiting.
const MailRetention = 48 * time.Hour

// ErrMailRateLimited: the org or the recipient has had too many emails.
var ErrMailRateLimited = errors.New("mail rate limit reached")

// Outbox statuses.
const (
	MailPending = "pending"
	MailSent    = "sent"
	MailFailed  = "failed"
)

// QueuedMail is a pending outbox message.
type QueuedMail struct {
	ID       int64
	OrgID    int64
	Kind     string
	To       string
	Subject  string
	Body     string
	Attempts int // failed attempts so far
}

// recipientHash identifies an address for rate limiting without storing
// it. With a secret box it is keyed, so the hash cannot be matched against
// guessed addresses.
func (s *Store) recipientHash(to string) []byte {
	if s.box != nil {
		return s.box.MAC("mail-rcpt\x00" + NormaliseEmail(to))
	}
	h := sha256.Sum256([]byte("augeo-mail-rcpt\x00" + NormaliseEmail(to)))
	return h[:]
}

// EnqueueInviteMail queues an invite email unless the org has queued
// MailOrgPerHour in the last hour or the recipient has had
// MailRecipientPerDay in the last day. The check and the insert run under
// one write lock, so concurrent invites cannot both slip under a limit.
func (s *Store) EnqueueInviteMail(ctx context.Context, orgID int64, to, subject, body string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	t := clock()
	// Writing first takes the write lock before the counts are read.
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_outbox WHERE status<>? AND updated<?`, MailPending, ts(t.Add(-MailRetention))); err != nil {
		return err
	}
	rh := s.recipientHash(to)
	day := ts(t.Add(-24 * time.Hour))
	var nOrg, nRcpt, nGlobal int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM mail_outbox WHERE org_id=? AND created>?),
		(SELECT COUNT(*) FROM mail_outbox WHERE recipient_hash=? AND org_id IS ? AND created>?),
		(SELECT COUNT(*) FROM mail_outbox WHERE recipient_hash=? AND created>?)`,
		orgID, ts(t.Add(-time.Hour)), rh, nullID(orgID), day, rh, day).Scan(&nOrg, &nRcpt, &nGlobal); err != nil {
		return err
	}
	if nOrg >= MailOrgPerHour || nRcpt >= MailRecipientPerDay || nGlobal >= MailRecipientGlobalPerDay {
		return ErrMailRateLimited
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_outbox(org_id, kind, recipient, recipient_hash, subject, body, next_attempt, created, updated)
		VALUES (?,?,?,?,?,?,?,?,?)`, nullID(orgID), "invite", to, rh, subject, body, ts(t), ts(t), ts(t)); err != nil {
		return err
	}
	return tx.Commit()
}

// DueMail returns up to limit pending messages whose next attempt is due.
func (s *Store) DueMail(ctx context.Context, limit int) ([]QueuedMail, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(org_id,0), kind, recipient, subject, body, attempts FROM mail_outbox
		WHERE status=? AND next_attempt<=? ORDER BY next_attempt, id LIMIT ?`, MailPending, now(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueuedMail
	for rows.Next() {
		var m QueuedMail
		if err := rows.Scan(&m.ID, &m.OrgID, &m.Kind, &m.To, &m.Subject, &m.Body, &m.Attempts); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkMailSent records a delivery and clears recipient and body.
func (s *Store) MarkMailSent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mail_outbox SET status=?, attempts=attempts+1, last_error='', recipient='', body='', updated=?
		WHERE id=? AND status=?`, MailSent, now(), id, MailPending)
	return err
}

// MarkMailRetry records a failed attempt and schedules the next one. code
// must be address-free (mail.ErrorCode).
func (s *Store) MarkMailRetry(ctx context.Context, id int64, code string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mail_outbox SET attempts=attempts+1, last_error=?, next_attempt=?, updated=? WHERE id=? AND status=?`,
		code, ts(next), now(), id, MailPending)
	return err
}

// MarkMailFailed records a final failure and clears recipient and body.
func (s *Store) MarkMailFailed(ctx context.Context, id int64, code string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mail_outbox SET status=?, attempts=attempts+1, last_error=?, recipient='', body='', updated=?
		WHERE id=? AND status=?`, MailFailed, code, now(), id, MailPending)
	return err
}

// PruneMail deletes finished rows older than MailRetention.
func (s *Store) PruneMail(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mail_outbox WHERE status<>? AND updated<?`, MailPending, ts(clock().Add(-MailRetention)))
	return err
}

// MailStatus is an outbox row without its content, for tests and
// operators.
type MailStatus struct {
	ID        int64
	Status    string
	Attempts  int
	LastError string
	HasBody   bool
	HasRcpt   bool
}

// MailStatuses lists outbox rows, oldest first.
func (s *Store) MailStatuses(ctx context.Context) ([]MailStatus, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, status, attempts, last_error, body<>'', recipient<>'' FROM mail_outbox ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MailStatus
	for rows.Next() {
		var m MailStatus
		if err := rows.Scan(&m.ID, &m.Status, &m.Attempts, &m.LastError, &m.HasBody, &m.HasRcpt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
