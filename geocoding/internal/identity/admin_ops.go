package identity

import (
	"context"
	"database/sql"
	"errors"
)

// ErrLastPlatformAdmin is returned when a change would leave no active
// platform admin.
var ErrLastPlatformAdmin = errors.New("identity: last active platform admin")

// otherActiveAdmins is true when an active platform admin other than the
// first bound id exists. Used inside single UPDATE statements so the check
// and the write cannot interleave with another request.
const otherActiveAdmins = `(SELECT COUNT(*) FROM users WHERE platform_admin=1 AND status='active' AND id<>?) > 0`

// ListUsers returns up to limit users for the platform admin, newest first,
// whose email contains q. before > 0 pages to older users (id < before);
// otherwise after > 0 pages to newer users (id > after, the page just above
// it), still returned newest first.
func (s *Store) ListUsers(ctx context.Context, q string, before, after int64, limit int) ([]User, error) {
	if limit <= 0 || limit > 501 {
		limit = 100
	}
	pat := "%" + likeEscape(q) + "%"
	var rows *sql.Rows
	var err error
	asc := false
	switch {
	case before > 0:
		rows, err = s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE email LIKE ? ESCAPE '\' AND id<? ORDER BY id DESC LIMIT ?`, pat, before, limit)
	case after > 0:
		asc = true
		rows, err = s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE email LIKE ? ESCAPE '\' AND id>? ORDER BY id ASC LIMIT ?`, pat, after, limit)
	default:
		rows, err = s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE email LIKE ? ESCAPE '\' ORDER BY id DESC LIMIT ?`, pat, limit)
	}
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
	if asc {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out, rows.Err()
}

// RevokePlatformAdmin removes platform admin from a user unless they are the
// last active platform admin (ErrLastPlatformAdmin). The check and the write
// are one statement.
func (s *Store) RevokePlatformAdmin(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET platform_admin=0 WHERE id=?
		AND (platform_admin=0 OR status<>'active' OR `+otherActiveAdmins+`)`, id, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return s.missingOrLast(ctx, id)
	}
	return nil
}

// SetUserStatusGuarded is SetUserStatus for the platform admin console: it
// refuses to suspend or deprovision the last active platform admin
// (ErrLastPlatformAdmin), checking and writing in one statement.
func (s *Store) SetUserStatusGuarded(ctx context.Context, id int64, status string) error {
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
	res, err := tx.ExecContext(ctx, `UPDATE users SET status=? WHERE id=?
		AND (?='active' OR platform_admin=0 OR status<>'active' OR `+otherActiveAdmins+`)`, status, id, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return s.missingOrLast(ctx, id)
	}
	if status != StatusActive {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) missingOrLast(ctx context.Context, id int64) error {
	if _, err := s.UserByID(ctx, id); err != nil {
		return err
	}
	return ErrLastPlatformAdmin
}

// SetOrgTierWith changes an org's quota tier and runs also (for example the
// API key update) in the same transaction, so both change or neither does.
func (s *Store) SetOrgTierWith(ctx context.Context, orgID int64, tier string, also func(*sql.Tx) error) error {
	if !validTier(tier) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE orgs SET tier=? WHERE id=?`, tier, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if also != nil {
		if err := also(tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validTier(tier string) bool {
	for _, t := range ValidTiers {
		if t == tier {
			return true
		}
	}
	return false
}
