package console

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"augeocoding/internal/identity"
)

// inviteMailResult says what happened to an invite email.
type inviteMailResult int

const (
	inviteMailOff     inviteMailResult = iota // no mail server configured
	inviteMailQueued                          // in the outbox; the worker sends it
	inviteMailLimited                         // over the org or recipient rate limit; not queued
	inviteMailFailed                          // configured, but queueing failed
)

// queueInviteEmail puts an invite email in the outbox and returns at once;
// the outbox worker delivers it with retries. A failure never fails the
// invite: it is logged (without the address) and reported to the caller.
func (s *Server) queueInviteEmail(r *http.Request, org identity.Org, inviter identity.User, to string, role identity.Role, expires time.Time) inviteMailResult {
	if !s.MailOn {
		return inviteMailOff
	}
	who := oneLine(inviter.Name)
	if who == "" {
		who = inviter.Email
	} else {
		who += " (" + inviter.Email + ")"
	}
	orgName := oneLine(org.Name)
	subject := "You are invited to " + orgName + " on au-geocoder"
	body := who + " invited you to join " + orgName + " on au-geocoder as " + role.String() + ".\n\n" +
		"To accept, sign in with this email address (" + to + "):\n\n" +
		"  " + s.abs("/auth/login") + "\n\n" +
		"The invitation expires on " + expires.UTC().Format("2 January 2006 15:04 MST") + ".\n\n" +
		"If you were not expecting this, you can ignore this email.\n"
	err := s.IDs.EnqueueInviteMail(r.Context(), org.ID, to, subject, body)
	switch {
	case err == nil:
		if s.MailWake != nil {
			s.MailWake()
		}
		return inviteMailQueued
	case errors.Is(err, identity.ErrMailRateLimited):
		s.Log.Warn("invite_email_rate_limited", "org_id", org.ID)
		return inviteMailLimited
	}
	s.Log.Error("invite_email_queue_failed", "org_id", org.ID, "error", strings.ReplaceAll(err.Error(), to, "<recipient>"))
	return inviteMailFailed
}

// oneLine collapses control characters (including CR and LF) to spaces so a
// user-chosen name cannot break a mail header or the message layout.
func oneLine(v string) string {
	return strings.Join(strings.FieldsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }), " ")
}
