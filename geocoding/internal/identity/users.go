package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// User statuses.
const (
	StatusActive        = "active"
	StatusSuspended     = "suspended"
	StatusDeprovisioned = "deprovisioned"
)

// User is a person.
type User struct {
	ID            int64
	Email         string
	Name          string
	Status        string
	PlatformAdmin bool
	Created       time.Time
	LastLogin     *time.Time
}

// Active reports whether the user may sign in.
func (u User) Active() bool { return u.Status == StatusActive }

// Org is a tenant.
type Org struct {
	ID          int64
	Slug        string
	Name        string
	Tier        string
	SSOEnforced bool
	JITEnabled  bool
	DefaultRole Role
	Personal    bool
	Created     time.Time
}

// Membership is a user's role in an org.
type Membership struct {
	Org     Org
	User    User
	Role    Role
	Source  string
	Created time.Time
}

// Invite is a pending membership for an email that has not signed in yet.
type Invite struct {
	ID        int64
	OrgID     int64
	Email     string
	Role      Role
	InvitedBy int64
	Created   time.Time
	Expires   time.Time
}

const userCols = `id, email, name, status, platform_admin, created, last_login`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var created string
	var last sql.NullString
	var admin int
	if err := sc.Scan(&u.ID, &u.Email, &u.Name, &u.Status, &admin, &created, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return u, ErrNotFound
		}
		return u, err
	}
	u.PlatformAdmin = admin != 0
	u.Created = parseTS(created)
	u.LastLogin = parseNullTS(last)
	return u, nil
}

// UserByID returns a user.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id))
}

// UserByEmail returns a user by email (case-insensitive).
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email=?`, NormaliseEmail(email)))
}

// CreateUser inserts a user.
func (s *Store) CreateUser(ctx context.Context, email, name string) (User, error) {
	email = NormaliseEmail(email)
	if !ValidEmail(email) {
		return User{}, ErrInvalid
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(email, name, created) VALUES (?,?,?)`, email, strings.TrimSpace(name), now())
	if err != nil {
		if isUnique(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return s.UserByID(ctx, id)
}

// ListUsers returns users for the platform admin, newest first.
func (s *Store) ListUsers(ctx context.Context, q string, limit int) ([]User, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE email LIKE ? ESCAPE '\' ORDER BY id DESC LIMIT ?`, "%"+likeEscape(q)+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserName updates the display name.
func (s *Store) SetUserName(ctx context.Context, id int64, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET name=? WHERE id=?`, strings.TrimSpace(name), id)
	return err
}

// SetUserStatus changes a user's status. Anything other than active deletes
// the user's sessions in the same transaction.
func (s *Store) SetUserStatus(ctx context.Context, id int64, status string) error {
	switch status {
	case StatusActive, StatusSuspended, StatusDeprovisioned:
	default:
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET status=? WHERE id=?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if status != StatusActive {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetPlatformAdmin grants or removes platform admin.
func (s *Store) SetPlatformAdmin(ctx context.Context, id int64, admin bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET platform_admin=? WHERE id=?`, b2i(admin), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountPlatformAdmins returns the number of active platform admins.
func (s *Store) CountPlatformAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE platform_admin=1 AND status='active'`).Scan(&n)
	return n, err
}

func (s *Store) touchLogin(ctx context.Context, userID int64) {
	s.db.ExecContext(ctx, `UPDATE users SET last_login=? WHERE id=?`, now(), userID)
}

// --- orgs ---

const orgCols = `id, slug, name, tier, sso_enforced, jit_enabled, default_role, personal, created`

func scanOrg(sc interface{ Scan(...any) error }) (Org, error) {
	var o Org
	var sso, jit, personal int
	var role, created string
	if err := sc.Scan(&o.ID, &o.Slug, &o.Name, &o.Tier, &sso, &jit, &role, &personal, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return o, ErrNotFound
		}
		return o, err
	}
	o.SSOEnforced, o.JITEnabled, o.Personal = sso != 0, jit != 0, personal != 0
	o.DefaultRole = ParseRole(role)
	o.Created = parseTS(created)
	return o, nil
}

var slugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

// ValidSlug reports whether s is a usable org or connection slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// Slugify makes a slug candidate from free text.
func Slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 40 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "org"
	}
	return out
}

// OrgByID returns an org.
func (s *Store) OrgByID(ctx context.Context, id int64) (Org, error) {
	return scanOrg(s.db.QueryRowContext(ctx, `SELECT `+orgCols+` FROM orgs WHERE id=?`, id))
}

// OrgBySlug returns an org.
func (s *Store) OrgBySlug(ctx context.Context, slug string) (Org, error) {
	return scanOrg(s.db.QueryRowContext(ctx, `SELECT `+orgCols+` FROM orgs WHERE slug=?`, slug))
}

// ListOrgs returns all orgs (platform admin).
func (s *Store) ListOrgs(ctx context.Context) ([]Org, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+orgCols+` FROM orgs ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// CreateOrg creates an org with owner as its first owner. If slug is taken
// and uniquify is set, a numeric suffix is added.
func (s *Store) CreateOrg(ctx context.Context, name, slug string, owner int64, personal, uniquify bool) (Org, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return Org{}, ErrInvalid
	}
	if slug == "" {
		slug = Slugify(name)
	}
	if !ValidSlug(slug) {
		return Org{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Org{}, err
	}
	defer tx.Rollback()
	base := slug
	var id int64
	for i := 1; ; i++ {
		res, err := tx.ExecContext(ctx, `INSERT INTO orgs(slug, name, personal, created) VALUES (?,?,?,?)`, slug, name, b2i(personal), now())
		if err == nil {
			id, _ = res.LastInsertId()
			break
		}
		if !isUnique(err) {
			return Org{}, err
		}
		if !uniquify || i > 50 {
			return Org{}, ErrConflict
		}
		suffix := fmt.Sprintf("-%d", i+1)
		if len(base)+len(suffix) > 40 {
			base = base[:40-len(suffix)]
		}
		slug = base + suffix
	}
	if owner != 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO memberships(org_id, user_id, role, source, created) VALUES (?,?,?,?,?)`,
			id, owner, RoleOwner.String(), "signup", now()); err != nil {
			return Org{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Org{}, err
	}
	return s.OrgByID(ctx, id)
}

// OrgSettings are the owner-editable org settings.
type OrgSettings struct {
	Name        string
	SSOEnforced bool
	JITEnabled  bool
	DefaultRole Role
}

// UpdateOrgSettings saves owner-editable settings.
func (s *Store) UpdateOrgSettings(ctx context.Context, orgID int64, set OrgSettings) error {
	name := strings.TrimSpace(set.Name)
	if name == "" || len(name) > 100 {
		return ErrInvalid
	}
	if set.DefaultRole < RoleViewer || set.DefaultRole > RoleAdmin {
		return ErrInvalid
	}
	res, err := s.db.ExecContext(ctx, `UPDATE orgs SET name=?, sso_enforced=?, jit_enabled=?, default_role=? WHERE id=?`,
		name, b2i(set.SSOEnforced), b2i(set.JITEnabled), set.DefaultRole.String(), orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ValidTiers are the quota tiers an org can hold (publicapi tiers, minus
// anonymous).
var ValidTiers = []string{"demo", "standard", "batch"}

// SetOrgTier changes an org's quota tier (platform admin only).
func (s *Store) SetOrgTier(ctx context.Context, orgID int64, tier string) error {
	ok := false
	for _, t := range ValidTiers {
		ok = ok || t == tier
	}
	if !ok {
		return ErrInvalid
	}
	res, err := s.db.ExecContext(ctx, `UPDATE orgs SET tier=? WHERE id=?`, tier, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteOrg deletes an org and everything it owns (cascade). API keys live
// in the publicapi tables; the caller revokes those first.
func (s *Store) DeleteOrg(ctx context.Context, orgID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM orgs WHERE id=?`, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- memberships ---

// Role returns the user's role in the org, RoleNone if not a member.
func (s *Store) Role(ctx context.Context, orgID, userID int64) (Role, error) {
	var r string
	err := s.db.QueryRowContext(ctx, `SELECT role FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&r)
	if errors.Is(err, sql.ErrNoRows) {
		return RoleNone, nil
	}
	if err != nil {
		return RoleNone, err
	}
	return ParseRole(r), nil
}

// UserOrgs returns the orgs a user belongs to with their role, by name.
func (s *Store) UserOrgs(ctx context.Context, userID int64) ([]Membership, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.id, o.slug, o.name, o.tier, o.sso_enforced, o.jit_enabled, o.default_role, o.personal, o.created, m.role, m.source, m.created
		FROM memberships m JOIN orgs o ON o.id=m.org_id WHERE m.user_id=? ORDER BY o.personal DESC, o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		var sso, jit, personal int
		var dr, oc, role, mc string
		if err := rows.Scan(&m.Org.ID, &m.Org.Slug, &m.Org.Name, &m.Org.Tier, &sso, &jit, &dr, &personal, &oc, &role, &m.Source, &mc); err != nil {
			return nil, err
		}
		m.Org.SSOEnforced, m.Org.JITEnabled, m.Org.Personal = sso != 0, jit != 0, personal != 0
		m.Org.DefaultRole = ParseRole(dr)
		m.Org.Created = parseTS(oc)
		m.Role = ParseRole(role)
		m.Created = parseTS(mc)
		out = append(out, m)
	}
	return out, rows.Err()
}

// Members lists an org's members.
func (s *Store) Members(ctx context.Context, orgID int64) ([]Membership, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, u.email, u.name, u.status, u.platform_admin, u.created, u.last_login, m.role, m.source, m.created
		FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=? ORDER BY u.email`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		var admin int
		var uc, role, mc string
		var last sql.NullString
		if err := rows.Scan(&m.User.ID, &m.User.Email, &m.User.Name, &m.User.Status, &admin, &uc, &last, &role, &m.Source, &mc); err != nil {
			return nil, err
		}
		m.User.PlatformAdmin = admin != 0
		m.User.Created = parseTS(uc)
		m.User.LastLogin = parseNullTS(last)
		m.Org.ID = orgID
		m.Role = ParseRole(role)
		m.Created = parseTS(mc)
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetMembership adds a member or changes their role. Demoting the last owner
// fails with ErrLastOwner.
func (s *Store) SetMembership(ctx context.Context, orgID, userID int64, role Role, source string) error {
	if role < RoleViewer || role > RoleOwner {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := setMembershipTx(ctx, tx, orgID, userID, role, source); err != nil {
		return err
	}
	return tx.Commit()
}

func setMembershipTx(ctx context.Context, tx *sql.Tx, orgID, userID int64, role Role, source string) error {
	var cur string
	err := tx.QueryRowContext(ctx, `SELECT role FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&cur)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO memberships(org_id, user_id, role, source, created) VALUES (?,?,?,?,?)`,
			orgID, userID, role.String(), source, now())
		return err
	case err != nil:
		return err
	}
	if ParseRole(cur) == RoleOwner && role != RoleOwner {
		if err := ensureAnotherOwner(ctx, tx, orgID, userID); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE memberships SET role=?, source=? WHERE org_id=? AND user_id=?`, role.String(), source, orgID, userID)
	return err
}

func ensureAnotherOwner(ctx context.Context, tx *sql.Tx, orgID, userID int64) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM memberships m JOIN users u ON u.id=m.user_id
		WHERE m.org_id=? AND m.role='owner' AND m.user_id<>? AND u.status='active'`, orgID, userID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrLastOwner
	}
	return nil
}

// RemoveMember removes a user from an org. Removing the last owner fails.
func (s *Store) RemoveMember(ctx context.Context, orgID, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cur string
	err = tx.QueryRowContext(ctx, `SELECT role FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if ParseRole(cur) == RoleOwner {
		if err := ensureAnotherOwner(ctx, tx, orgID, userID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM memberships WHERE org_id=? AND user_id=?`, orgID, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// --- invites ---

// CreateInvite invites an email to an org; re-inviting refreshes role and
// expiry.
func (s *Store) CreateInvite(ctx context.Context, orgID int64, email string, role Role, by int64, ttl time.Duration) error {
	email = NormaliseEmail(email)
	if !ValidEmail(email) || role < RoleViewer || role > RoleOwner {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO invites(org_id, email, role, invited_by, created, expires) VALUES (?,?,?,?,?,?)
		ON CONFLICT(org_id, email) DO UPDATE SET role=excluded.role, invited_by=excluded.invited_by, created=excluded.created, expires=excluded.expires`,
		orgID, email, role.String(), nullID(by), now(), ts(clock().Add(ttl)))
	return err
}

// Invites lists an org's pending invites.
func (s *Store) Invites(ctx context.Context, orgID int64) ([]Invite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, email, role, COALESCE(invited_by,0), created, expires FROM invites WHERE org_id=? AND expires>? ORDER BY email`, orgID, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var in Invite
		var role, c, e string
		if err := rows.Scan(&in.ID, &in.OrgID, &in.Email, &role, &in.InvitedBy, &c, &e); err != nil {
			return nil, err
		}
		in.Role, in.Created, in.Expires = ParseRole(role), parseTS(c), parseTS(e)
		out = append(out, in)
	}
	return out, rows.Err()
}

// DeleteInvite removes an invite within an org.
func (s *Store) DeleteInvite(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM invites WHERE org_id=? AND id=?`, orgID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// hasInvite reports whether any unexpired invite exists for email.
func (s *Store) hasInvite(ctx context.Context, email string) bool {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM invites WHERE email=? AND expires>?`, NormaliseEmail(email), now()).Scan(&n)
	return n > 0
}

// acceptInvites turns a user's pending invites into memberships. An invite
// never lowers an existing role.
func (s *Store) acceptInvites(ctx context.Context, u User) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT org_id, role FROM invites WHERE email=? AND expires>?`, u.Email, now())
	if err != nil {
		return nil, err
	}
	type inv struct {
		org  int64
		role Role
	}
	var invs []inv
	for rows.Next() {
		var i inv
		var r string
		if err := rows.Scan(&i.org, &r); err != nil {
			rows.Close()
			return nil, err
		}
		i.role = ParseRole(r)
		invs = append(invs, i)
	}
	rows.Close()
	var orgs []int64
	for _, i := range invs {
		var cur string
		err := tx.QueryRowContext(ctx, `SELECT role FROM memberships WHERE org_id=? AND user_id=?`, i.org, u.ID).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err := tx.ExecContext(ctx, `INSERT INTO memberships(org_id, user_id, role, source, created) VALUES (?,?,?,?,?)`, i.org, u.ID, i.role.String(), "invite", now()); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else if ParseRole(cur) < i.role {
			if _, err := tx.ExecContext(ctx, `UPDATE memberships SET role=? WHERE org_id=? AND user_id=?`, i.role.String(), i.org, u.ID); err != nil {
				return nil, err
			}
		}
		orgs = append(orgs, i.org)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM invites WHERE email=?`, u.Email); err != nil {
		return nil, err
	}
	return orgs, tx.Commit()
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
