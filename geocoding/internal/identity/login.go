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
	IdPSID       string
	IDToken      string
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
			if d := s.enforcedSSO(ctx, u.Email, u); d != nil {
				return LoginResult{}, d
			}
		}
		s.db.ExecContext(ctx, `UPDATE identities SET last_login=?, email=? WHERE connection_id=? AND subject=?`, now(), a.Email, c.ID, a.Subject)
		if err := s.afterLogin(ctx, u, a, p); err != nil {
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
		}
	} else {
		// 3. Platform connection.
		u, err = s.UserByEmail(ctx, a.Email)
		if d := s.enforcedSSO(ctx, a.Email, u); d != nil {
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
	if err := s.afterLogin(ctx, u, a, p); err != nil {
		return LoginResult{}, err
	}
	u, err = s.UserByID(ctx, u.ID)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{User: u, Created: created}, nil
}

// enforcedSSO denies a platform login (or a passkey login, by callers) for an
// address whose domain belongs to an org that enforces SSO. Owners of that
// org and platform admins are exempt so they keep break-glass access.
func (s *Store) enforcedSSO(ctx context.Context, email string, u User) *Denial {
	org, err := s.OrgForDomain(ctx, EmailDomain(email))
	if err != nil || !org.SSOEnforced {
		return nil
	}
	if u.ID != 0 {
		if u.PlatformAdmin {
			return nil
		}
		if r, _ := s.Role(ctx, org.ID, u.ID); r == RoleOwner {
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
	return s.enforcedSSO(ctx, u.Email, u)
}

// afterLogin applies invites, bootstrap admin, org-connection membership and
// group mappings, and gives a member-less user a personal org.
func (s *Store) afterLogin(ctx context.Context, u User, a Assertion, p LoginPolicy) error {
	trusted := a.EmailTrusted && strings.EqualFold(u.Email, a.Email)
	c := a.Connection
	if !c.Platform() && s.orgHasVerifiedDomain(ctx, c.OrgID, EmailDomain(u.Email)) {
		// Verified-domain org connections vouch for the address.
		trusted = true
	}
	if trusted {
		if _, err := s.acceptInvites(ctx, u); err != nil {
			return err
		}
		if p.bootstrap(u.Email) && !u.PlatformAdmin {
			if err := s.SetPlatformAdmin(ctx, u.ID, true); err != nil {
				return err
			}
			s.Audit(ctx, AuditEvent{ActorID: u.ID, Actor: "system", Action: "platform_admin.bootstrap", Target: u.Email})
		}
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
		name := u.Name
		if name == "" {
			name = strings.SplitN(u.Email, "@", 2)[0]
		}
		if _, err := s.CreateOrg(ctx, name+"'s workspace", Slugify(strings.SplitN(u.Email, "@", 2)[0]), u.ID, true, true); err != nil {
			return err
		}
	}
	return nil
}
