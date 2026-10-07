package console

import (
	"errors"
	"net/http"
	"regexp"
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
	// Names are chosen by users, so they go in quotes with anything that
	// looks like a link defused; the only link is the platform's own.
	who := mailName(inviter.Name)
	if who == "" {
		who = inviter.Email
	} else {
		who = `"` + who + `" (` + inviter.Email + ")"
	}
	orgName := `"` + mailName(org.Name) + `"`
	subject := "Invitation to the organisation " + orgName + " on au-geocoder"
	body := who + " invited you to join the organisation " + orgName + " on au-geocoder as " + role.String() + ".\n" +
		"Organisation and person names are chosen by au-geocoder users, not by au-geocoder.\n\n" +
		"To accept, sign in with this email address (" + to + ") at the address below, then accept the invitation on your console home page:\n\n" +
		"  " + s.abs("/auth/login") + "\n\n" +
		"The invitation expires on " + expires.UTC().Format("2 January 2006 15:04 MST") + ".\n\n" +
		"If you were not expecting this, ignore this email; nothing happens unless you accept.\n"
	err := s.IDs.EnqueueInviteMailFrom(r.Context(), org.ID, inviter.ID, to, subject, body)
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

var (
	mailSchemeRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*:/+`)
	mailWWWRe    = regexp.MustCompile(`(?i)\bwww\.`)
	// A dot between two letters or digits is how a host name is written
	// ("evil.example", "login.evil.example").
	mailDotRe = regexp.MustCompile(`([\p{L}\p{N}])[.。．｡]+([\p{L}\p{N}])`)
)

// mailName makes a user-chosen name safe to quote in platform mail: one
// line, no double quotes, no scheme ("https://"), no "www." and no dotted
// host-like tokens, so a mail client has nothing to turn into a link.
func mailName(v string) string {
	v = oneLine(v)
	v = strings.ReplaceAll(v, `"`, "'")
	v = mailSchemeRe.ReplaceAllString(v, "")
	v = mailWWWRe.ReplaceAllString(v, "")
	for mailDotRe.MatchString(v) {
		v = mailDotRe.ReplaceAllString(v, "$1 $2")
	}
	return oneLine(v)
}

// oneLine collapses control characters (including CR and LF) to spaces so a
// user-chosen name cannot break a mail header or the message layout.
func oneLine(v string) string {
	return strings.Join(strings.FieldsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }), " ")
}
