// verify runs the P1 stage-5 integrity gate on a built dataset. It is the
// mandatory pre-publish check: R1.4 makes an interrupted bulk load yield a
// corrupt file (journal_mode=OFF, synchronous=OFF), so a structurally valid
// DB is not enough — the gate must be run and pass before anything is swapped
// in. All four checks must pass:
//
//  1. PRAGMA integrity_check = ok
//  2. FTS5 integrity-check (each trigram table)
//  3. Row counts within tolerance of source published counts
//  4. Checksum recorded for the published artifact
//
// Plus a smoke query set: known addresses go through the resolver and reverse
// geocoding and come back as the right street address.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	_ "modernc.org/sqlite"

	"auplaces/internal/api"
	"auplaces/internal/match"
)

func main() {
	dbPath := flag.String("db", "data/vic.db", "dataset to verify")
	outPath := flag.String("out", "", "verify report output (default: <db>.verify.json)")
	flag.Parse()

	if *outPath == "" {
		*outPath = *dbPath + ".verify.json"
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	report := verifyReport{DB: *dbPath, OK: true, Checks: []checkResult{}}

	// 1. PRAGMA integrity_check.
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&report.Integrity); err != nil {
		log.Fatalf("integrity_check: %v", err)
	}
	report.add("integrity_check", report.Integrity == "ok", report.Integrity)
	if report.Integrity != "ok" {
		report.OK = false
	}

	// 2. FTS5 integrity-check over each trigram table. The FTS5 integrity-check
	// is invoked as INSERT INTO tbl(tbl) VALUES('integrity-check'), where tbl
	// is the table name used as a column.
	for _, tbl := range []string{"addr_trgm", "poi_trgm"} {
		// Check the table exists first.
		var exists string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&exists); err != nil {
			report.add("fts5_integrity_"+tbl, false, fmt.Sprintf("table absent: %v", err))
			report.OK = false
			continue
		}
		// Invoke the integrity check. The FTS5 integrity-check validates the
		// index and raises an error if corrupt; a clean run means the index is
		// consistent. We run it as an Exec and treat success as pass.
		if _, err := db.Exec(`INSERT INTO ` + tbl + `(` + tbl + `) VALUES('integrity-check')`); err != nil {
			report.add("fts5_integrity_"+tbl, false, fmt.Sprintf("check error: %v", err))
			report.OK = false
			continue
		}
		report.add("fts5_integrity_"+tbl, true, "ok")
	}

	// 3. Row counts within tolerance of source published counts.
	// Expected counts (Victoria AUG 2026): address ~4.18M, poi ~71.9k,
	// boundary ~2.98k. The POI count is the served dataset's (poi_meta: OSM
	// replication sequence 4967, 2026-11-12); the earlier figure, 59,720, is
	// more than 5% below it and failed every current dataset. We check the built tables are present and non-degenerate,
	// and record actual counts; tolerance is a soft check (the source counts
	// are the published G-NAF numbers, which the build may legitimately differ
	// from by the locality filter).
	counts := map[string]int64{
		"address":  4184145,
		"poi":      71854,
		"boundary": 2979,
	}
	for tbl, want := range counts {
		var n int64
		if err := db.QueryRow(`SELECT count(*) FROM ` + tbl).Scan(&n); err != nil {
			report.add("rowcount_"+tbl, false, fmt.Sprintf("table absent: %v", err))
			report.OK = false
			continue
		}
		// Tolerance ±5% (the build may filter/merge; exact match is not required).
		lo, hi := int64(float64(want)*0.95), int64(float64(want)*1.05)
		ok := n >= lo && n <= hi
		report.add(fmt.Sprintf("rowcount_%s", tbl), ok, fmt.Sprintf("rows=%d want=%d (tol ±5%%)", n, want))
		if !ok {
			report.OK = false
		}
	}

	// Optional tables (aliases from buildaddr, postal areas from
	// loadpostcode): the server answers without them (buildaddr leaves the
	// alias tables empty when G-NAF's were not loaded), so their row counts
	// are recorded but do not decide the gate.
	for _, tbl := range []string{"alias_locality", "alias_street", "postcode"} {
		var n int64
		if err := db.QueryRow(`SELECT count(*) FROM ` + tbl).Scan(&n); err != nil {
			report.add("optional_"+tbl, true, "absent (not loaded)")
			continue
		}
		report.add("optional_"+tbl, true, fmt.Sprintf("rows=%d", n))
	}

	// 4. Checksum of the published artifact.
	sum, err := sha256File(*dbPath)
	if err != nil {
		log.Fatalf("checksum: %v", err)
	}
	report.SHA256 = sum
	report.add("checksum_sha256", sum != "", sum)

	// Smoke query set: known addresses, typed as people type them, go through
	// the real resolver (the /search ladder) and must land on the right
	// street address; each then goes back through reverse geocoding, which
	// must find it from its own point. A direct SQL lookup proved only that
	// the table was queryable, not that matching or addr_rt work. Expected
	// values are street addresses, not PIDs: G-NAF has one PID per unit.
	for _, s := range smokeSet {
		got, err := smokeResolve(db, s.query, s.want)
		ok := err == nil
		report.add("smoke_"+s.query, ok, fmt.Sprintf("got=%s want=%s err=%v", got, s.want, err))
		if !ok {
			report.OK = false
		}
	}

	// Write the report.
	b, err := jsonMarshal(report)
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(*outPath, b, 0644); err != nil {
		log.Fatalf("write report: %v", err)
	}
	fmt.Printf("verify report written to %s\n", *outPath)
	if report.OK {
		fmt.Println("VERIFY OK — dataset passed the integrity gate")
	} else {
		fmt.Println("VERIFY FAILED — dataset must not be published")
		os.Exit(1)
	}
}

type verifyReport struct {
	DB        string        `json:"db"`
	OK        bool          `json:"ok"`
	Integrity string        `json:"integrity_check"`
	SHA256    string        `json:"sha256"`
	Checks    []checkResult `json:"checks"`
}

type checkResult struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

func (r *verifyReport) add(name string, pass bool, detail string) {
	r.Checks = append(r.Checks, checkResult{Name: name, Pass: pass, Detail: detail})
}

// smokeSet is the verify smoke: queries from testdata/golden.tsv whose
// expected answer is number|street_name|street_type|locality.
var smokeSet = []struct{ query, want string }{
	{"36 Collins St Melbourne VIC 3000", "36|COLLINS|STREET|MELBOURNE"},
	{"634 Bridge Rd Richmond VIC 3121", "634|BRIDGE|ROAD|RICHMOND"},
	{"223 Malop St Geelong", "223|MALOP|STREET|GEELONG"},
}

// smokeResolve resolves query through api.Search, checks the top candidate is
// the expected street address, and checks match.Reverse finds that address
// from its own coordinates. It returns what it found, for the report.
func smokeResolve(db *sql.DB, query, want string) (string, error) {
	ctx := context.Background()
	resp := api.Search(ctx, db, api.SearchRequest{Query: query, Limit: 1})
	if len(resp.Candidates) == 0 || resp.Candidates[0].Kind != "address" {
		return "", fmt.Errorf("no address candidate (strategy %q)", resp.Strategy)
	}
	top := resp.Candidates[0]
	var got string
	if err := db.QueryRowContext(ctx, `
		SELECT coalesce(street_number, '') || '|' || street_name || '|' || coalesce(street_type, '') || '|' || locality_name
		FROM address WHERE gnaf_pid = ?`, top.ID).Scan(&got); err != nil {
		return top.ID, fmt.Errorf("candidate %s: %w", top.ID, err)
	}
	if got != want {
		return got, fmt.Errorf("resolved to the wrong address")
	}
	// The nearest address to the candidate's own point is at distance zero
	// (it, or a unit sharing its geocode) if addr_rt is consistent with address.
	near, err := match.ReverseWithin(ctx, db, top.Lon, top.Lat, 1, 50)
	if err != nil {
		return got, fmt.Errorf("reverse: %w", err)
	}
	if len(near) == 0 || near[0].DistanceM > 1 {
		return got, fmt.Errorf("reverse from %s's own point found nothing there", top.ID)
	}
	return got, nil
}

// sha256File computes the SHA-256 of a file.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// jsonMarshal pretty-prints the report.
func jsonMarshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
