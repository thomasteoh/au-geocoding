package api

import (
	"context"
	"database/sql"
	"strings"
	"sync"

	"auplaces/internal/match"
)

// matchSets are the per-dataset lookup sets the address path needs: the known
// locality names (to classify tokens), the fuzzy set (typo-tolerant
// generation), and the states and postcodes the dataset covers (to tell a
// query for another state from one this dataset can answer, see scope.go). Building them scans the whole address table, so they are built
// once per open dataset and reused; a dataset swap brings a new *sql.DB and
// therefore its own sets.
type matchSets struct {
	localities map[string]bool
	fuzzy      *match.FuzzySet
	states     map[string]bool // state abbreviations (VIC, NSW, ...)
	postcodes  map[string]bool
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
	states, err := distinct(ctx, db, `SELECT DISTINCT state FROM address`)
	if err != nil {
		return nil, err
	}
	postcodes, err := distinct(ctx, db, `SELECT DISTINCT postcode FROM address WHERE postcode <> ''`)
	if err != nil {
		return nil, err
	}
	s = &matchSets{localities: fs.Localities(), fuzzy: fs, states: states, postcodes: postcodes}
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

// distinct collects the single text column query returns. Both uses read an
// indexed column, so the scan stays in the index.
func distinct(ctx context.Context, db *sql.DB, query string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if v.String != "" {
			out[strings.ToUpper(v.String)] = true
		}
	}
	return out, rows.Err()
}
