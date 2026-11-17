package api

import (
	"context"
	"database/sql"
	"sync"

	"auplaces/internal/match"
)

// matchSets are the per-dataset lookup sets the address path needs: the known
// locality names (to classify tokens) and the fuzzy set (typo-tolerant
// generation). Building them scans the whole address table, so they are built
// once per open dataset and reused; a dataset swap brings a new *sql.DB and
// therefore its own sets.
type matchSets struct {
	localities map[string]bool
	fuzzy      *match.FuzzySet
}

var (
	setsMu    sync.Mutex
	setsByDB  = map[*sql.DB]*matchSets{}
	setsBuild = map[*sql.DB]*sync.Mutex{}
)

// setsFor returns the lookup sets for db, building them on first use. Concurrent
// first callers wait for one build rather than each scanning the table. The
// build ignores the caller's context so one cancelled request cannot leave the
// dataset without sets; a failed build is not cached and is retried next call.
func setsFor(db *sql.DB) (*matchSets, error) {
	setsMu.Lock()
	if s, ok := setsByDB[db]; ok {
		setsMu.Unlock()
		return s, nil
	}
	b, ok := setsBuild[db]
	if !ok {
		b = &sync.Mutex{}
		setsBuild[db] = b
	}
	setsMu.Unlock()

	b.Lock()
	defer b.Unlock()
	setsMu.Lock()
	s, ok := setsByDB[db]
	setsMu.Unlock()
	if ok {
		return s, nil
	}

	ctx := context.Background()
	fs, err := match.LoadFuzzySet(ctx, db)
	if err != nil {
		return nil, err
	}
	s = &matchSets{localities: fs.Localities(), fuzzy: fs}
	setsMu.Lock()
	setsByDB[db] = s
	delete(setsBuild, db)
	setsMu.Unlock()
	return s, nil
}

// ForgetSets drops the cached sets for a dataset that is no longer served.
func ForgetSets(db *sql.DB) {
	setsMu.Lock()
	delete(setsByDB, db)
	setsMu.Unlock()
}

// WarmSets builds the lookup sets for db ahead of the first request.
func WarmSets(db *sql.DB) error {
	_, err := setsFor(db)
	return err
}
