package identity

import (
	"context"
	"time"
)

// Session proofs record every connection a browser session has signed in
// through, so one session can satisfy SSO enforcement in several orgs. A
// new sign-in by the same user carries the previous session's proofs into
// the new session (the session ID still rotates, A1).

// AddSessionProofs records connections on a session. Unknown connections
// are skipped.
func (s *Store) AddSessionProofs(ctx context.Context, idHash []byte, connectionIDs ...int64) error {
	for _, c := range connectionIDs {
		if c == 0 {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO session_proofs(id_hash, connection_id, created)
			SELECT ?, id, ? FROM connections WHERE id=?`, idHash, now(), c); err != nil {
			return err
		}
	}
	return nil
}

// SessionProofs lists the connections a session has signed in through,
// including the one that created it.
func (s *Store) SessionProofs(ctx context.Context, idHash []byte) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT connection_id FROM session_proofs WHERE id_hash=?
		UNION SELECT connection_id FROM sessions WHERE id_hash=? AND connection_id IS NOT NULL`, idHash, idHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var c int64
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SessionSatisfiesOrg reports whether a session signed in through one of
// the org's own connections within maxAge (0 = any age, bounded by the
// session's own lifetime).
func (s *Store) SessionSatisfiesOrg(ctx context.Context, idHash []byte, orgID int64, maxAge time.Duration) bool {
	since := "0000"
	if maxAge > 0 {
		since = ts(clock().Add(-maxAge))
	}
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (
		SELECT p.connection_id FROM session_proofs p JOIN connections c ON c.id=p.connection_id
			WHERE p.id_hash=? AND c.org_id=? AND p.created>=?
		UNION ALL
		SELECT s.connection_id FROM sessions s JOIN connections c ON c.id=s.connection_id
			WHERE s.id_hash=? AND c.org_id=? AND s.created>=?)`, idHash, orgID, since, idHash, orgID, since).Scan(&n)
	return n > 0
}

// DropUserProofs removes a connection's proofs from all of a user's
// sessions (after unlinking it).
func (s *Store) DropUserProofs(ctx context.Context, userID, connectionID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM session_proofs WHERE connection_id=? AND id_hash IN (SELECT id_hash FROM sessions WHERE user_id=?)`,
		connectionID, userID)
	return err
}

// CarrySessionProofs copies an old session's proofs, and the connection that
// created it, into a new session of the same user, keeping their original
// times so a proof never outlives the session lifetime it was earned under.
func (s *Store) CarrySessionProofs(ctx context.Context, oldHash, newHash []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO session_proofs(id_hash, connection_id, created)
		SELECT ?, p.connection_id, p.created FROM session_proofs p JOIN sessions o ON o.id_hash=p.id_hash JOIN sessions n ON n.id_hash=?
			WHERE p.id_hash=? AND o.user_id=n.user_id
		UNION ALL
		SELECT ?, o.connection_id, o.created FROM sessions o JOIN sessions n ON n.id_hash=?
			WHERE o.id_hash=? AND o.connection_id IS NOT NULL AND o.user_id=n.user_id`,
		newHash, newHash, oldHash, newHash, newHash, oldHash)
	return err
}
