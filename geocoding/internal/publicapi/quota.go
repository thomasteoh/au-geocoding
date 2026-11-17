package publicapi

import (
	"database/sql"
	"errors"
	"time"
)

// TierLLMQuota is the daily cap on LLM-rung calls per usage key (org or
// operator key). The LLM is the only rung with a per-call cost, so it has a
// ceiling of its own on top of the row quota.
var TierLLMQuota = map[Tier]int64{
	TierAnonymous: 0, // anonymous uses AnonLLM (per IP + global), not this
	TierDemo:      50,
	TierStandard:  1000,
	TierBatch:     5000,
}

// ErrLLMQuotaExceeded is returned when a principal has used its daily LLM
// calls.
var ErrLLMQuotaExceeded = errors.New("daily llm quota exceeded")

// QuotaRemaining returns how many result rows the principal may still be
// charged today. Anonymous principals are accounted per IP elsewhere and
// report -1 (not applicable).
func (s *Store) QuotaRemaining(p Principal) (int64, error) {
	if p.Anonymous() || p.Tier == TierAnonymous {
		return -1, nil
	}
	cur, err := s.UsageToday(p.UsageKey)
	if err != nil {
		return 0, err
	}
	left := TierQuota[p.Tier] - cur
	if left < 0 {
		left = 0
	}
	return left, nil
}

// ReserveRows takes up to want rows from the principal's remaining quota for
// today, before the work that will produce them, and returns how many it got
// (0 when none are left). The caller does no more work than the grant pays
// for, then settles with RefundRows for whatever it did not use. Charging
// after the work instead lets a caller near its ceiling have the work done
// and then be refused — work done for free, repeatably.
func (s *Store) ReserveRows(p Principal, want int64) (int64, error) {
	if p.Anonymous() || p.Tier == TierAnonymous {
		// Anonymous callers are reserved per IP (ReserveAnonRows); a key on
		// the anonymous tier has no row quota to draw on.
		return 0, nil
	}
	if p.UsageKey == "" {
		return 0, errors.New("reserve: empty principal")
	}
	if want <= 0 {
		return 0, nil
	}
	day := time.Now().UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur int64
	err = tx.QueryRow(`SELECT rows FROM usage_principal WHERE principal=? AND day=?`, p.UsageKey, day).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	grant := min(want, TierQuota[p.Tier]-cur)
	if grant <= 0 {
		return 0, nil
	}
	if _, err := tx.Exec(`INSERT INTO usage_principal(principal, day, rows) VALUES (?,?,?)
		ON CONFLICT(principal, day) DO UPDATE SET rows=rows+excluded.rows`, p.UsageKey, day, grant); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return grant, nil
}

// RefundRows returns n reserved-but-unused rows to today's quota. It never
// takes the count below zero. A reservation made just before UTC midnight and
// settled after it refunds into the new day's row, which is then clamped:
// the caller loses at most the unused part of one request.
func (s *Store) RefundRows(p Principal, n int64) error {
	if n <= 0 || p.Anonymous() || p.Tier == TierAnonymous || p.UsageKey == "" {
		return nil
	}
	day := time.Now().UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE usage_principal SET rows = MAX(rows - ?, 0) WHERE principal=? AND day=?`, n, p.UsageKey, day)
	return err
}

// ChargeLLMCall counts one LLM-rung call against the principal's daily
// usage_principal.llm_calls, refusing it once TierLLMQuota is reached. It
// runs before the provider is called, so a refused call costs nothing.
func (s *Store) ChargeLLMCall(p Principal) error {
	if p.Anonymous() || p.Tier == TierAnonymous || p.UsageKey == "" {
		return ErrLLMQuotaExceeded
	}
	limit := TierLLMQuota[p.Tier]
	if limit <= 0 {
		return ErrLLMQuotaExceeded
	}
	day := time.Now().UTC().Format("2006-01-02")
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cur int64
	err = tx.QueryRow(`SELECT llm_calls FROM usage_principal WHERE principal=? AND day=?`, p.UsageKey, day).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if cur+1 > limit {
		return ErrLLMQuotaExceeded
	}
	if _, err := tx.Exec(`INSERT INTO usage_principal(principal, day, rows, llm_calls) VALUES (?,?,0,1)
		ON CONFLICT(principal, day) DO UPDATE SET llm_calls=llm_calls+1`, p.UsageKey, day); err != nil {
		return err
	}
	return tx.Commit()
}

// LLMCallsToday returns the LLM calls charged to a usage key today.
func (s *Store) LLMCallsToday(usageKey string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT llm_calls FROM usage_principal WHERE principal=? AND day=?`, usageKey, time.Now().UTC().Format("2006-01-02")).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}
