// gen also generates a corpus of deliberately-corrupted queries (corpus.md:
// "mostly deliberately-corrupted real G-NAF rows"). It runs after seeding the
// synthetic DB, picking real PIDs and corrupting them.
//
// For the spike, the corpus is written to testdata/corpus.tsv by the seed step;
// gen reads it. A separate --corpus-gen flag produces it from the DB.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"strings"
)

// genCorpus builds a TSV of (query, expected-pid) pairs from the synthetic DB,
// deliberately corrupting some queries to exercise the two-stage matcher.
func genCorpus(ctx context.Context, db *sql.DB, n int, outPath string) error {
	rows, err := db.QueryContext(ctx, `
		SELECT gnaf_pid, street_number, street_name, street_type, locality_name,
		       state, postcode
		FROM address ORDER BY gnaf_pid
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type rowT struct {
		pid, num, name, typ, loc, state, post string
	}
	var all []rowT
	for rows.Next() {
		var r rowT
		if err := rows.Scan(&r.pid, &r.num, &r.name, &r.typ, &r.loc, &r.state, &r.post); err != nil {
			return err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	rnd := rand.New(rand.NewSource(7))
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header comment.
	fmt.Fprintln(f, "# query<TAB>expected-pid — deliberately-corrupted corpus")

	// Sample n rows; corrupt ~60%.
	for i := 0; i < n && i < len(all); i++ {
		r := all[rnd.Intn(len(all))]
		query := fmt.Sprintf("%s %s %s %s", r.num, r.name, r.loc, r.state)
		if r.num != "" {
			// Strip the trailing .0 from REAL-cast numbers (87.0 → 87) — a
			// user types "87", not "87.0". The normaliser would split 87.0
			// into 87 + 0 (the regex strips the dot), breaking the number.
			query = strings.Replace(query, r.num, strings.TrimSuffix(r.num, ".0"), 1)
			query = strings.TrimSpace(query)
		}
		// Corrupt: typo a street name or locality with probability 0.6.
		if rnd.Intn(10) < 6 {
			// Pick a token to corrupt.
			switch rnd.Intn(3) {
			case 0:
				query = typoStreet(query, r.name, rnd)
			case 1:
				query = typoLocality(query, r.loc, rnd)
			case 2:
				query = dropToken(query, rnd)
			}
		}
		fmt.Fprintf(f, "%s	%s\n", query, r.pid)
	}
	return nil
}

func typoStreet(q, name string, rnd *rand.Rand) string {
	// Replace name with a 1-char typo (transposition or substitution).
	if len(name) < 2 {
		return q
	}
	pos := rnd.Intn(len(name))
	b := []byte(name)
	// Substitution: swap two adjacent chars if possible.
	if rnd.Intn(2) == 0 && pos+1 < len(b) {
		b[pos], b[pos+1] = b[pos+1], b[pos]
	} else {
		b[pos] = byte('a' + rnd.Intn(26))
	}
	typo := string(b)
	return strings.Replace(q, name, typo, 1)
}

func typoLocality(q, loc string, rnd *rand.Rand) string {
	if len(loc) < 2 {
		return q
	}
	pos := rnd.Intn(len(loc))
	b := []byte(loc)
	if rnd.Intn(2) == 0 && pos+1 < len(b) {
		b[pos], b[pos+1] = b[pos+1], b[pos]
	} else {
		b[pos] = byte('a' + rnd.Intn(26))
	}
	typo := string(b)
	return strings.Replace(q, loc, typo, 1)
}

func dropToken(q string, rnd *rand.Rand) string {
	fields := strings.Fields(q)
	if len(fields) < 2 {
		return q
	}
	drop := 1 + rnd.Intn(len(fields)-1) // never drop the first
	fields = append(fields[:drop], fields[drop+1:]...)
	return strings.Join(fields, " ")
}
