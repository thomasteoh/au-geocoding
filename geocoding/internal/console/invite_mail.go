package console

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"augeocoding/internal/identity"
	"augeocoding/internal/mail"
)

// inviteMailResult says what happened to an invite email.
type inviteMailResult int

const (
	inviteMailOff    inviteMailResult = iota // no mail server configured
	inviteMailSent                           // handed to the mail server
	inviteMailFailed                         // configured, but sending failed
)

// sendInviteEmail emails an invitee. A failure never fails the invite: it
// is logged (without the address) and reported back to the caller.
func (s *Server) sendInviteEmail(r *http.Request, org identity.Org, inviter identity.User, to string, role identity.Role, expires time.Time) inviteMailResult {
	if s.Mail == nil {
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
	ctx, cancel := context.WithTimeout(r.Context(), mail.Timeout)
	defer cancel()
	err := s.Mail.Send(ctx, to, subject, body)
	switch {
	case err == nil:
		return inviteMailSent
	case errors.Is(err, mail.ErrDisabled):
		return inviteMailOff
	}
	// SMTP replies often echo the recipient; keep addresses out of logs.
	msg := strings.ReplaceAll(err.Error(), to, "<recipient>")
	s.Log.Warn("invite_email_failed", "org_id", org.ID, "error", msg)
	return inviteMailFailed
}

// oneLine collapses control characters (including CR and LF) to spaces so a
// user-chosen name cannot break a mail header or the message layout.
func oneLine(v string) string {
	return strings.Join(strings.FieldsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }), " ")
}
