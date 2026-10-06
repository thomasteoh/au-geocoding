package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Explicit account linking (docs/auth.md "Linking sign-in methods"). A
// signed-in person proves control of a second identity by completing its
// sign-in; it is then attached to their account. Unlike automatic linking at
// login, this needs no email match, because the person holds both.

// ErrLinkedElsewhere is returned when the identity already belongs to
// another account.
var ErrLinkedElsewhere = errors.New("this sign-in is already linked to another account")

// ErrLastMethod is returned when unlinking would leave no way to sign in.
var ErrLastMethod = errors.New("cannot remove your only way to sign in")

// LinkedIdentity is an identity row with its connection, for the account
// page.
type LinkedIdentity struct {
	ID         int64
	Connection Connection
	Email      string
	Created    time.Time
	LastLogin  *time.Time
}

// LinkIdentity attaches a verified assertion to an existing user. For an
// org connection the asserted email must be in a domain that org verified
// (the same bar as signing in), and the org's membership rules (invites,
// JIT, group mappings) apply as at login.
func (s *Store) LinkIdentity(ctx context.Context, userID int64, a Assertion, p LoginPolicy) error {
	c := a.Connection
	if !c.Enabled || a.Subject == "" {
		return ErrInvalid
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !u.Active() {
		return ErrInvalid
	}
	email := NormaliseEmail(a.Email)
	if !c.Platform() && !s.orgHasVerifiedDomain(ctx, c.OrgID, EmailDomain(email)) {
		return &Denial{Code: "domain_not_verified", Message: "That account's email domain is not verified for this organisation."}
	}
	var owner int64
	err = s.db.QueryRowContext(ctx, `SELECT user_id FROM identities WHERE connection_id=? AND subject=?`, c.ID, a.Subject).Scan(&owner)
	switch {
	case err == nil && owner == userID:
		return nil
	case err == nil:
		return ErrLinkedElsewhere
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO identities(user_id, connection_id, subject, email, created, last_login) VALUES (?,?,?,?,?,?)`,
		userID, c.ID, a.Subject, email, now(), now()); err != nil {
		if isUnique(err) {
			return ErrLinkedElsewhere
		}
		return err
	}
	if !c.Platform() {
		// Membership follows the org's rules; a link that grants no
		// membership is still a valid sign-in method.
		if err := s.afterLogin(ctx, u, a, p, false); err != nil {
			var d *Denial
			if !errors.As(err, &d) {
				return err
			}
		}
	}
	return nil
}

// LinkedIdentities lists a user's identities.
func (s *Store) LinkedIdentities(ctx context.Context, userID int64) ([]LinkedIdentity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, connection_id, email, created, last_login FROM identities WHERE user_id=? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	type row struct {
		id, conn int64
		email    string
		c        string
		l        sql.NullString
	}
	var raw []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.conn, &r.email, &r.c, &r.l); err != nil {
			rows.Close()
			return nil, err
		}
		raw = append(raw, r)
	}
	rows.Close()
	var out []LinkedIdentity
	for _, r := range raw {
		c, err := s.ConnectionByID(ctx, r.conn)
		if err != nil {
			continue
		}
		c.ClientSecret, c.SAMLSPKey = "", ""
		out = append(out, LinkedIdentity{ID: r.id, Connection: c, Email: r.email, Created: parseTS(r.c), LastLogin: parseNullTS(r.l)})
	}
	return out, nil
}

// UnlinkIdentity removes one of the user's identities, refusing to remove
// the last sign-in method (identities plus passkeys). Sessions created
// through that identity's connection end.
func (s *Store) UnlinkIdentity(ctx context.Context, userID, identityID int64) (Connection, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Connection{}, err
	}
	defer tx.Rollback()
	var connID int64
	err = tx.QueryRowContext(ctx, `SELECT connection_id FROM identities WHERE id=? AND user_id=?`, identityID, userID).Scan(&connID)
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, ErrNotFound
	}
	if err != nil {
		return Connection{}, err
	}
	var methods int
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM identities WHERE user_id=?) + (SELECT COUNT(*) FROM passkeys WHERE user_id=?)`,
		userID, userID).Scan(&methods); err != nil {
		return Connection{}, err
	}
	if methods <= 1 {
		return Connection{}, ErrLastMethod
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM identities WHERE id=? AND user_id=?`, identityID, userID); err != nil {
		return Connection{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND connection_id=?`, userID, connID); err != nil {
		return Connection{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM session_proofs WHERE connection_id=? AND id_hash IN (SELECT id_hash FROM sessions WHERE user_id=?)`,
		connID, userID); err != nil {
		return Connection{}, err
	}
	if err := tx.Commit(); err != nil {
		return Connection{}, err
	}
	c, err := s.ConnectionByID(ctx, connID)
	c.ClientSecret, c.SAMLSPKey = "", ""
	return c, err
}

// LinkableConnections are the enabled connections a user may link: platform
// connections and those of orgs they belong to.
func (s *Store) LinkableConnections(ctx context.Context, userID int64) ([]Connection, error) {
	conns, err := s.LoginConnections(ctx)
	if err != nil {
		return nil, err
	}
	orgs, err := s.UserOrgs(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, m := range orgs {
		oc, err := s.OrgLoginConnections(ctx, m.Org.ID)
		if err != nil {
			return nil, err
		}
		conns = append(conns, oc...)
	}
	for i := range conns {
		conns[i].ClientSecret, conns[i].SAMLSPKey = "", ""
	}
	return conns, nil
}

