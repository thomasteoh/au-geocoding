package publicapi

import (
	"context"
	"database/sql"
	"strings"
)

// noScope is stored when stripping batch would leave a key with no scopes:
// an empty scope set means "search" (hasScope's historical default), so a
// batch-only key must not silently gain search on a downgrade.
const noScope = "none"

// SetOrgTierTx moves every key of an org to a new tier inside the caller's
// transaction. Leaving the batch tier also strips the batch scope from the
// org's keys, so a key minted under the batch tier cannot keep calling
// /batch after a downgrade. It does not touch the in-memory index: call
// ApplyOrgTier after the transaction commits.
func (s *Store) SetOrgTierTx(ctx context.Context, tx *sql.Tx, orgID int64, tier Tier) error {
	if _, err := tx.ExecContext(ctx, `UPDATE api_keys SET quota_tier=? WHERE org_id=?`, tierName(tier), orgID); err != nil {
		return err
	}
	if tier == TierBatch {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, scopes FROM api_keys WHERE org_id=?`, orgID)
	if err != nil {
		return err
	}
	type upd struct {
		id     int64
		scopes string
	}
	var ups []upd
	for rows.Next() {
		var id int64
		var sc string
		if err := rows.Scan(&id, &sc); err != nil {
			rows.Close()
			return err
		}
		if next, changed := stripBatch(strings.Fields(sc)); changed {
			ups = append(ups, upd{id, strings.Join(next, " ")})
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, u := range ups {
		if _, err := tx.ExecContext(ctx, `UPDATE api_keys SET scopes=? WHERE id=?`, u.scopes, u.id); err != nil {
			return err
		}
	}
	return nil
}

// ApplyOrgTier updates the in-memory index after SetOrgTierTx committed.
func (s *Store) ApplyOrgTier(orgID int64, tier Tier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, k := range s.keys {
		if k.OrgID == orgID {
			k.Tier = tier
			if tier != TierBatch {
				if next, changed := stripBatch(k.Scopes); changed {
					k.Scopes = next
				}
			}
			s.keys[p] = k
		}
	}
}

// stripBatch removes the batch scope. A key left with nothing gets noScope.
func stripBatch(scopes []string) ([]string, bool) {
	var out []string
	changed := false
	for _, sc := range scopes {
		if strings.EqualFold(sc, "batch") {
			changed = true
			continue
		}
		out = append(out, sc)
	}
	if !changed {
		return scopes, false
	}
	if len(out) == 0 {
		out = []string{noScope}
	}
	return out, true
}
