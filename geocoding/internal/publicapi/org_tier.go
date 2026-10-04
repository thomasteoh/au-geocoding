package publicapi

import (
	"context"
	"database/sql"
)

// SetOrgTierTx moves every key of an org to a new tier inside the caller's
// transaction. It does not touch the in-memory index: call ApplyOrgTier
// after the transaction commits.
func (s *Store) SetOrgTierTx(ctx context.Context, tx *sql.Tx, orgID int64, tier Tier) error {
	_, err := tx.ExecContext(ctx, `UPDATE api_keys SET quota_tier=? WHERE org_id=?`, tierName(tier), orgID)
	return err
}

// ApplyOrgTier updates the in-memory index after SetOrgTierTx committed.
func (s *Store) ApplyOrgTier(orgID int64, tier Tier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, k := range s.keys {
		if k.OrgID == orgID {
			k.Tier = tier
			s.keys[p] = k
		}
	}
}
