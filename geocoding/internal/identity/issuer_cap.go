package identity

import (
	"context"
	"errors"
)

// MaxJWTIssuersPerOrg caps how many JWT issuer registrations an org may
// hold. Each registration is a JWKS the server may fetch and a row the
// bearer path scans, so an org admin must not be able to add them without
// bound.
const MaxJWTIssuersPerOrg = 10

// ErrTooManyIssuers is returned by SaveJWTIssuer when the org is at the cap.
var ErrTooManyIssuers = errors.New("too many jwt issuers for this org")

// insertJWTIssuer inserts j only while the org holds fewer than
// MaxJWTIssuersPerOrg issuers. The count and the insert are one statement,
// so concurrent saves cannot overshoot the cap.
func (s *Store) insertJWTIssuer(ctx context.Context, j JWTIssuer, subs string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO jwt_issuers(org_id, issuer, audience, jwks_url, scope_prefix, allowed_subjects, enabled, created)
		SELECT ?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM jwt_issuers WHERE org_id=?) < ?`,
		j.OrgID, j.Issuer, j.Audience, j.JWKSURL, j.ScopePrefix, subs, b2i(j.Enabled), now(), j.OrgID, MaxJWTIssuersPerOrg)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrTooManyIssuers
	}
	return res.LastInsertId()
}
