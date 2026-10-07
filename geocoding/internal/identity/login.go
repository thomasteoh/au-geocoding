package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Assertion is what every login protocol produces after it has verified the
// IdP's response. Only verified data goes in here.
type Assertion struct {
	Connection   Connection
	Subject      string // stable IdP subject (OIDC sub, GitHub numeric id, SAML NameID)
	Email        string
	EmailTrusted bool // the IdP vouches for the address (per preset + email_verified)
	Name         string
	Groups       []string
	// GroupsUnknown is set when the IdP could not say which groups the
	// person is in (Entra group overage with no Graph lookup). Roles are
	// then left as they are rather than recomputed from an empty list.
	GroupsUnknown bool
	IdPSID        string
	IdPSubQual    NameIDQualifiers // SAML only
	IDToken       string
}

// Denial is a login refusal with a reason code for the audit log and a
// message that is safe to show the person.
type Denial struct {
	Code    string
	Message string
	// SSOOrg is set when the person must use their org's SSO instead.
	SSOOrg string
}

func (d *Denial) Error() string { return "login denied: " + d.Code }

func deny(code, msg string) error { return &Denial{Code: code, Message: msg} }

// LoginPolicy is deployment configuration that affects login.
type LoginPolicy struct {
	SignupOpen      bool
	BootstrapAdmins []string // emails promoted to platform admin on first trusted login
}

func (p LoginPolicy) bootstrap(email string) bool {
	for _, e := range p.BootstrapAdmins {
		if NormaliseEmail(e) == email && email != "" {
			return true
		}
	}
	return false
}

// LoginResult is the outcome of ResolveLogin.
type LoginResult struct {
	User    User
	Created bool
}

// ResolveLogin turns a verified assertion into a user, following auth.md
// "Resolving a login to a user". It never links on an untrusted email (A2).
func (s *Store) ResolveLogin(ctx context.Context, a Assertion, p LoginPolicy) (LoginResult, error) {
	c := a.Connection
	if !c.Enabled {
		return LoginResult{}, deny("connection_disabled", "This sign-in method is disabled.")
	}
	if a.Subject == "" {
		return LoginResult{}, deny("no_subject", "The identity provider did not identify you.")
	}
	a.Email = NormaliseEmail(a.Email)
	if a.Email != "" && !ValidEmail(a.Email) {
		a.Email = ""
		a.EmailTrusted = false
	}

	// 1. Known identity.
	var userID int64
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM identities WHERE connection_id=? AND subject=?`, c.ID, a.Subject).Scan(&userID)
	if err == nil {
		u, err := s.UserByID(ctx, userID)
		if err != nil {
			return LoginResult{}, err
		}
		if !u.Active() {
			return LoginResult{}, deny("user_"+u.Status, "Your account is "+u.Status+".")
		}
		// A platform login is still subject to later SSO enforcement on the
		// person's email domain.
		if c.Platform() {
			if d := s.enforcedSSO(ctx, u.Email, u, false); d != nil {
				return LoginResult{}, d
			}
		}
		s.db.ExecContext(ctx, `UPDATE identities SET last_login=?, email=? WHERE connection_id=? AND subject=?`, now(), a.Email, c.ID, a.Subject)
		if err := s.afterLogin(ctx, u, a, p, false); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{User: u}, nil
	}

	// Every path below needs an email to find or create a user.
	if a.Email == "" {
		return LoginResult{}, deny("no_email", "The identity provider did not share an email address.")
	}
	domain := EmailDomain(a.Email)

	var u User
	created := false
	if !c.Platform() {
		// 2. Org connection: the address must be in a domain the org verified.
		if !s.orgHasVerifiedDomain(ctx, c.OrgID, domain) {
			return LoginResult{}, deny("domain_not_verified", "Your email domain is not verified for this organisation.")
		}
		org, err := s.OrgByID(ctx, c.OrgID)
		if err != nil {
			return LoginResult{}, err
		}
		u, err = s.UserByEmail(ctx, a.Email)
		switch {
		case errors.Is(err, ErrNotFound):
			if !org.JITEnabled && !s.hasInvite(ctx, a.Email) && !p.bootstrap(a.Email) {
				return LoginResult{}, deny("not_provisioned", "You do not have access to this organisation yet. Ask an admin to invite you.")
			}
			if u, err = s.CreateUser(ctx, a.Email, a.Name); err != nil {
				return LoginResult{}, err
			}
			created = true
		case err != nil:
			return LoginResult{}, err
		default:
			// An org connection is configured by that org's own owners and its
			// IdP decides what email it asserts, so it may only take over
			// accounts that belong to the org anyway. Anyone with access
			// elsewhere (other orgs, platform admin) links only by signing in
			// the way they did before (A2).
			ok, err := s.orgLinkable(ctx, u, c.OrgID)
			if err != nil {
				return LoginResult{}, err
			}
			if !ok {
				return LoginResult{}, deny("link_not_allowed", "An account with this email already exists outside this organisation. Sign in the way you did before, then link this sign-in method from your account page.")
			}
		}
	} else {
		// 3. Platform connection.
		u, err = s.UserByEmail(ctx, a.Email)
		if d := s.enforcedSSO(ctx, a.Email, u, false); d != nil {
			return LoginResult{}, d
		}
		switch {
		case errors.Is(err, ErrNotFound):
			// Never create an account on an address the IdP does not vouch
			// for: whoever later signs in with a trusted provider for that
			// address would inherit an account the first person controls
			// (pre-account hijacking, A2).
			if !a.EmailTrusted {
				return LoginResult{}, deny("email_not_trusted", "This sign-in method did not verify your email address.")
			}
			if !p.SignupOpen && !s.hasInvite(ctx, a.Email) && !p.bootstrap(a.Email) {
				return LoginResult{}, deny("signup_closed", "Sign-up is closed. Ask an admin for an invitation.")
			}
			if u, err = s.CreateUser(ctx, a.Email, a.Name); err != nil {
				return LoginResult{}, err
			}
			created = true
		case err != nil:
			return LoginResult{}, err
		default:
			if !a.EmailTrusted {
				return LoginResult{}, deny("email_not_trusted", "An account with this email already exists. Sign in with the method you used before.")
			}
		}
	}
	if !u.Active() {
		return LoginResult{}, deny("user_"+u.Status, "Your account is "+u.Status+".")
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO identities(user_id, connection_id, subject, email, created, last_login) VALUES (?,?,?,?,?,?)`,
		u.ID, c.ID, a.Subject, a.Email, now(), now()); err != nil {
		if isUnique(err) {
			// A concurrent login linked it first; retry as a known identity.
			return s.ResolveLogin(ctx, a, p)
		}
		return LoginResult{}, err
	}
	if err := s.afterLogin(ctx, u, a, p, created); err != nil {
		// A denied first login must not leave the identity linked, or the
		// next login would skip every check above as a known identity.
		s.db.ExecContext(ctx, `DELETE FROM identities WHERE connection_id=? AND subject=?`, c.ID, a.Subject)
		return LoginResult{}, err
	}
	u, err = s.UserByID(ctx, u.ID)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{User: u, Created: created}, nil
}

// enforcedSSO denies a platform login or a passkey login for an address
// whose domain belongs to an org that enforces SSO. Platform admins are
// exempt; owners of that org are exempt only for passkeys (allowOwner), their
// break-glass path when the IdP is down.
func (s *Store) enforcedSSO(ctx context.Context, email string, u User, allowOwner bool) *Denial {
	org, err := s.OrgForDomain(ctx, EmailDomain(email))
	if err != nil || !org.SSOEnforced {
		return nil
	}
	if u.ID != 0 {
		if u.PlatformAdmin {
			return nil
		}
		if r, _ := s.Role(ctx, org.ID, u.ID); allowOwner && r == RoleOwner {
			return nil
		}
	}
	return &Denial{Code: "sso_required", Message: fmt.Sprintf("%s requires you to sign in with its single sign-on.", org.Name), SSOOrg: org.Slug}
}

func (s *Store) membership(ctx context.Context, orgID, userID int64) (Role, string, error) {
	var r, src string
	err := s.db.QueryRowContext(ctx, `SELECT role, source FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&r, &src)
	if errors.Is(err, sql.ErrNoRows) {
		return RoleNone, "", nil
	}
	return ParseRole(r), src, err
}

// EnforcedSSO is the exported check for passkey login.
func (s *Store) EnforcedSSO(ctx context.Context, u User) *Denial {
	return s.enforcedSSO(ctx, u.Email, u, true)
}

// orgLinkable reports whether an org connection may attach a new identity to
// u: u is not a platform admin and belongs to no org other than orgID and
// their own personal workspace.
func (s *Store) orgLinkable(ctx context.Context, u User, orgID int64) (bool, error) {
	return orgLinkableQ(ctx, s.db, u, orgID)
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// orgLinkableQ is orgLinkable on a DB or transaction.
func orgLinkableQ(ctx context.Context, q rowQuerier, u User, orgID int64) (bool, error) {
	if u.PlatformAdmin {
		return false, nil
	}
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM memberships m JOIN orgs o ON o.id=m.org_id
		WHERE m.user_id=? AND m.org_id<>? AND NOT (o.personal=1 AND m.role='owner'
			AND (SELECT COUNT(*) FROM memberships x WHERE x.org_id=o.id)=1)`, u.ID, orgID).Scan(&n)
	return n == 0, err
}

// afterLogin applies an org connection's own invites, bootstrap admin, org-connection membership and
// group mappings, and gives a member-less user a personal org.
func (s *Store) afterLogin(ctx context.Context, u User, a Assertion, p LoginPolicy, created bool) error {
	trusted := a.EmailTrusted && strings.EqualFold(u.Email, a.Email)
	c := a.Connection
	if !c.Platform() {
		// The org's SCIM deactivated this person: no way back in through
		// SSO, JIT or the org's invites until SCIM reactivates them.
		if off, err := s.scimInactive(ctx, c.OrgID, u.ID); err != nil {
			return err
		} else if off {
			return deny("scim_inactive", "Your access to this organisation has been removed.")
		}
		// Invites are otherwise accepted only explicitly in the console
		// (auth.md "Invites"). An org connection's IdP vouches for the
		// address within its own org, and orgLinkable already bounds whom it
		// can sign in, so that org's own invites are accepted here.
		if trusted || s.orgHasVerifiedDomain(ctx, c.OrgID, EmailDomain(u.Email)) {
			if _, err := s.acceptInvites(ctx, u, c.OrgID); err != nil {
				return err
			}
		}
	}
	// Bootstrap applies once, when the account is created through a trusted
	// address; a platform admin who later revokes it stays revoked.
	if trusted && created && p.bootstrap(u.Email) && !u.PlatformAdmin {
		if err := s.SetPlatformAdmin(ctx, u.ID, true); err != nil {
			return err
		}
		s.Audit(ctx, AuditEvent{ActorID: u.ID, Actor: "system", Action: "platform_admin.bootstrap", Target: u.Email})
	}
	if !c.Platform() {
		org, err := s.OrgByID(ctx, c.OrgID)
		if err != nil {
			return err
		}
		cur, curSource, err := s.membership(ctx, org.ID, u.ID)
		if err != nil {
			return err
		}
		mapped, hasMappings, err := s.MappedRole(ctx, org.ID, c.ID, a.Groups)
		if err != nil {
			return err
		}
		switch {
		case a.GroupsUnknown:
			// Keep the current role; JIT still applies to newcomers.
			if cur == RoleNone && org.JITEnabled {
				if err := s.SetMembership(ctx, org.ID, u.ID, org.DefaultRole, "jit"); err != nil {
					return err
				}
			}
		case hasMappings && mapped != RoleNone:
			if mapped != cur {
				if err := s.SetMembership(ctx, org.ID, u.ID, mapped, "group"); err != nil && !errors.Is(err, ErrLastOwner) {
					return err
				}
			}
		case hasMappings && curSource == "group":
			// The role came from a group the person is no longer in.
			if org.JITEnabled {
				err = s.SetMembership(ctx, org.ID, u.ID, org.DefaultRole, "jit")
			} else {
				err = s.RemoveMember(ctx, org.ID, u.ID)
			}
			if err != nil && !errors.Is(err, ErrLastOwner) {
				return err
			}
		case cur == RoleNone && org.JITEnabled:
			if err := s.SetMembership(ctx, org.ID, u.ID, org.DefaultRole, "jit"); err != nil {
				return err
			}
		}
		if r, _ := s.Role(ctx, org.ID, u.ID); r == RoleNone {
			return deny("not_member", "You do not have access to this organisation yet. Ask an admin to invite you.")
		}
	}
	orgs, err := s.UserOrgs(ctx, u.ID)
	if err != nil {
		return err
	}
	if len(orgs) == 0 {
		// Someone with an invite waiting decides on it in the console
		// first; a personal workspace would only add a quota they did not
		// ask for.
		if pending, err := s.UserInvites(ctx, u); err != nil {
			return err
		} else if len(pending) > 0 {
			return nil
		}
		name := u.Name
		if name == "" {
			name = strings.SplitN(u.Email, "@", 2)[0]
		}
		if r := []rune(name); len(r) > 60 {
			name = string(r[:60])
		}
		_, err := s.CreateOrg(ctx, name+"'s workspace", Slugify(strings.SplitN(u.Email, "@", 2)[0]), u.ID, true, true)
		if errors.Is(err, ErrConflict) {
			// Every numbered variant is taken (squatted); fall back to random.
			_, err = s.CreateOrg(ctx, name+"'s workspace", "ws-"+strings.ToLower(RandomToken(6)), u.ID, true, true)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
