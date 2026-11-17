package identity

import (
	"context"
	"database/sql"
	"errors"
)

// Tenant abuse limits and explicit invite acceptance (docs/auth.md
// "Invites", "Org limits").

// ErrOrgLimit: the user has created as many orgs as they may.
var ErrOrgLimit = errors.New("organisation limit reached")

func (s *Store) defaultTier() string {
	for _, t := range ValidTiers {
		if t == s.DefaultOrgTier {
			return t
		}
	}
	return "demo"
}

// CreateOrgLimited creates a non-personal org owned by owner, failing with
// ErrOrgLimit if owner has already created maxOwned live non-personal orgs
// (maxOwned <= 0: no limit). Platform admins are exempt. The count and the
// insert share one transaction.
func (s *Store) CreateOrgLimited(ctx context.Context, name, slug string, owner int64, maxOwned int) (Org, error) {
	return s.createOrg(ctx, name, slug, owner, false, true, maxOwned)
}

func orgLimitTx(ctx context.Context, tx *sql.Tx, owner int64, maxOwned int) error {
	var n, admin int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM orgs WHERE created_by=? AND personal=0), platform_admin FROM users WHERE id=?`,
		owner, owner).Scan(&n, &admin); err != nil {
		return err
	}
	if admin == 0 && n > maxOwned {
		return ErrOrgLimit
	}
	return nil
}

// DeleteOrgWith deletes an org (cascade) and runs inTx, if set, in the same
// transaction: the console revokes the org's API keys there, so a key
// issued concurrently is either revoked here or refused by IssueKey's org
// check after the commit.
func (s *Store) DeleteOrgWith(ctx context.Context, orgID int64, inTx func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM orgs WHERE id=?`, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if inTx != nil {
		if err := inTx(tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// OrgExistsTx returns ErrNotFound unless the org exists, as seen by tx.
// Key issuance calls it after its insert, under the write lock.
func OrgExistsTx(ctx context.Context, tx *sql.Tx, orgID int64) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM orgs WHERE id=?`, orgID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PendingInvite is an invite as its recipient sees it.
type PendingInvite struct {
	ID        int64
	OrgID     int64
	OrgName   string
	OrgSlug   string
	Role      Role
	InvitedBy string // inviter's email, "" if unknown
	Expires   string
}

// UserInvites lists the unexpired invites for the user's email.
func (s *Store) UserInvites(ctx context.Context, u User) ([]PendingInvite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT i.id, i.org_id, o.name, o.slug, i.role, COALESCE(b.email, ''), i.expires
		FROM invites i JOIN orgs o ON o.id=i.org_id LEFT JOIN users b ON b.id=i.invited_by
		WHERE i.email=? AND i.expires>? ORDER BY o.name`, u.Email, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingInvite
	for rows.Next() {
		var p PendingInvite
		var role, exp string
		if err := rows.Scan(&p.ID, &p.OrgID, &p.OrgName, &p.OrgSlug, &role, &p.InvitedBy, &exp); err != nil {
			return nil, err
		}
		p.Role = ParseRole(role)
		p.Expires = parseTS(exp).UTC().Format("2 Jan 2006")
		out = append(out, p)
	}
	return out, rows.Err()
}

// AcceptInvite turns one of the user's own invites into a membership (an
// invite never lowers an existing role) and deletes it. An invite for
// another address, or an expired one, is ErrNotFound.
func (s *Store) AcceptInvite(ctx context.Context, u User, inviteID int64) (Org, Role, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Org{}, RoleNone, err
	}
	defer tx.Rollback()
	// Delete first: it takes the write lock and makes acceptance single-use.
	var orgID int64
	var role string
	err = tx.QueryRowContext(ctx, `DELETE FROM invites WHERE id=? AND email=? AND expires>? RETURNING org_id, role`,
		inviteID, u.Email, now()).Scan(&orgID, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, RoleNone, ErrNotFound
	}
	if err != nil {
		return Org{}, RoleNone, err
	}
	if err := joinFromInviteTx(ctx, tx, orgID, u.ID, ParseRole(role)); err != nil {
		return Org{}, RoleNone, err
	}
	org, err := scanOrg(tx.QueryRowContext(ctx, `SELECT `+orgCols+` FROM orgs WHERE id=?`, orgID))
	if err != nil {
		return Org{}, RoleNone, err
	}
	if err := tx.Commit(); err != nil {
		return Org{}, RoleNone, err
	}
	r, err := s.Role(ctx, orgID, u.ID)
	return org, r, err
}

// DeclineInvite deletes one of the user's own invites.
func (s *Store) DeclineInvite(ctx context.Context, u User, inviteID int64) (Org, error) {
	var orgID int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM invites WHERE id=? AND email=? RETURNING org_id`, inviteID, u.Email).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	if err != nil {
		return Org{}, err
	}
	return s.OrgByID(ctx, orgID)
}

// SharedJWTIssuers returns the IDs of the org's issuer registrations whose
// (issuer, audience) another org has also registered. Tokens for such a
// pair are refused as ambiguous; the console warns without naming the
// other org.
func (s *Store) SharedJWTIssuers(ctx context.Context, orgID int64) (map[int64]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT j.id FROM jwt_issuers j WHERE j.org_id=? AND EXISTS (
		SELECT 1 FROM jwt_issuers o WHERE o.issuer=j.issuer AND o.audience=j.audience AND o.org_id<>j.org_id)`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
