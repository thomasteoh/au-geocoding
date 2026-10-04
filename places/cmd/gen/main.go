// gen seeds a synthetic Victoria-shaped DB and runs the two-stage matcher
// over a small corpus, reporting match rate and generation breadth.
// Step 1's measurement harness — synthetic now, real-data-swappable later.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"auplaces/internal/match"
	"auplaces/internal/normalise"
	"auplaces/internal/schema"
)

func main() {
	dbPath := flag.String("db", "testdata/vic.db", "path to synthetic DB")
	n := flag.Int("n", 2000, "number of synthetic rows")
	corpus := flag.String("corpus", "testdata/corpus.tsv", "corpus file (query<TAB>expected-pid)")
	genCorpusOnly := flag.Bool("gen-corpus", false, "generate corpus from DB and exit")
	real := flag.Bool("real", false, "use real G-NAF DB (data/vic.db), skip synthetic seed")
	capN := flag.Int("cap", 0, "max candidates per query (0=uncapped; INV-8 bounded generation)")
	limit := flag.Int("limit", 0, "run at most N corpus queries (0=all); CI subset uses this (R9.3)")
	flag.Parse()

	ctx := context.Background()

	// Real-data mode: skip synthetic seeding, use the real DB.
	if !*real {
		// Build synthetic DB if it doesn't exist or --rebuild.
		// Env follows the D-020 convention: AUGEO_ prefix (the geocoder does the
		// same; bare names would collide with unrelated env in the caller).
		rebuild := os.Getenv("AUGEO_REBUILD") == "1" || !fileExists(*dbPath)
		if rebuild {
			db, err := schema.BuildSynthetic(*dbPath, *n, 42)
			if err != nil {
				log.Fatalf("seed: %v", err)
			}
			db.Close()
		}
	}

	db, err := openDB(*dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Corpus generation mode: build corpus TSV from the DB, exit.
	if *genCorpusOnly {
		if err := genCorpus(ctx, db, 500, *corpus); err != nil {
			log.Fatalf("gen-corpus: %v", err)
		}
		fmt.Printf("corpus generated: %s\n", *corpus)
		return
	}

	// Load corpus.
	queries := loadCorpus(*corpus)

	// Load the locality set from the DB — the normaliser needs it to classify
	// locality tokens as reliable anchors.
	localitySet := map[string]bool{}
	{
		rows, err := db.QueryContext(ctx, `SELECT DISTINCT locality_name FROM address`)
		if err != nil {
			log.Fatalf("locality set: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				log.Fatalf("scan locality: %v", err)
			}
			localitySet[strings.ToUpper(l)] = true
		}
		if err := rows.Err(); err != nil {
			log.Fatalf("locality set rows: %v", err)
		}
	}

	// Load the fuzzy set (locality + street names) for typo-tolerant
	// generation — a typo'd locality/street resolves to its near-match.
	fs, err := match.LoadFuzzySet(ctx, db)
	if err != nil {
		log.Fatalf("fuzzy set: %v", err)
	}

	var matchRate float64
	var genBreadthTotal, genBreadthN int
	var latencies []float64

	matched := 0
	for i, q := range queries {
		// CI subset (R9.3): run at most the limit; a subset is a smoke, not a
		// full accuracy run (that happens before release against real data).
		if *limit > 0 && i >= *limit {
			break
		}
		rel, score, fields := normalise.Tokenise(q.text, 32, localitySet)
		qm := match.Query{Reliable: rel, Score: score, Fields: fields}
		start := time.Now()
		cands, err := match.Generate(ctx, db, qm, fs, *capN)
		if err != nil {
			log.Printf("generate %q: %v", q.text, err)
			continue
		}
		latency := time.Since(start).Seconds() * 1000 // ms
		latencies = append(latencies, latency)

		genBreadthTotal += len(cands)
		genBreadthN++

		// Score and pick best.
		best := ""
		bestScore := -1.0
		for _, c := range cands {
			s := match.Score(qm, c)
			if s > bestScore {
				bestScore = s
				best = c.PID
			}
		}
		// Match at the street-address level: G-NAF has unit-level duplicates
		// (e.g. UNIT 1 / UNIT 2 at 87 DERRICK LALOR). A query that omits the
		// unit is ambiguous — any address at that street number is a valid
		// match. Compare the candidate's street address (number+street+locality
		// +state) against the want-pid's street address, not the exact PID.
		if best == q.want {
			matched++
		} else if best != "" {
			// Look up the best candidate's street address + the want's.
			bestAddr := lookupStreetAddr(db, best)
			wantAddr := lookupStreetAddr(db, q.want)
			if bestAddr != "" && bestAddr == wantAddr {
				matched++
			}
		}
	}

	runCount := len(queries)
	if *limit > 0 && *limit < runCount {
		runCount = *limit
	}
	matchRate = float64(matched) / float64(runCount)
	fmt.Printf("corpus: %d queries (ran %d)\n", len(queries), runCount)
	fmt.Printf("match rate: %.3f (%d/%d)\n", matchRate, matched, runCount)
	fmt.Printf("avg generation breadth: %.0f (total %d / %d)\n",
		float64(genBreadthTotal)/float64(genBreadthN), genBreadthTotal, genBreadthN)
	sort.Float64s(latencies)
	if len(latencies) > 0 {
		p50 := latencies[len(latencies)/2]
		p99 := latencies[int(float64(len(latencies))*0.99)-1]
		fmt.Printf("latency: p50 %.2f ms | p99 %.2f ms (n=%d)\n", p50, p99, len(latencies))
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// lookupStreetAddr returns the street-address key (number+street+locality+state)
// for a PID, for street-address-level match comparison. Empty if not found.
func lookupStreetAddr(db *sql.DB, pid string) string {
	if pid == "" {
		return ""
	}
	var num, st, loc, stt, state string
	err := db.QueryRow(
		`SELECT street_number, street_name, locality_name, street_type, state
		 FROM address WHERE gnaf_pid = ?`, pid,
	).Scan(&num, &st, &loc, &stt, &state)
	if err != nil {
		return ""
	}
	// Key: number|street|type|locality|state (unit-level duplicates collapse
	// to the same street address, which is what the query resolves to).
	return num + "|" + st + "|" + stt + "|" + loc + "|" + state
}

func openDB(p string) (*sql.DB, error) {
	// Ensure parent dir exists.
	if dir := filepath.Dir(p); dir != "" {
		_ = os.MkdirAll(dir, 0755)
	}
	return sql.Open("sqlite", p)
}
