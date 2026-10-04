// oscchain applies OSM daily diffs in sequence, driven by the poi_meta
// as-of anchor (R2.5). It reads the anchor from poi_meta, fetches the next
// OSC change file from the OSM replication feed, applies it via loadoscdiff,
// and advances the anchor — looping until the feed has no newer file. This is
// the incremental per-source path: it keeps the poi layer current without a
// full PBF reload. It is INV-4-safe: it writes only to the pipeline DB's poi
// layer, never to a live swap.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"compress/gzip"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"auplaces/internal/schema"
)

// state is the parsed replication state (sequenceNumber + timestamp).
type state struct {
	Sequence  uint64
	Timestamp string
}

// fetchState retrieves and parses the feed's state.txt. The geofabrik
// sequenceNumber is the feed's own counter; timestamp is the as-of point
// (colons escaped as \: in the file).
func fetchState(rawURL string) (state, error) {
	resp, err := fetchDiff(rawURL)
	if err != nil {
		return state{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return state{}, fmt.Errorf("fetch %s: status %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return state{}, err
	}
	var st state
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "sequenceNumber=") {
			v := strings.TrimPrefix(line, "sequenceNumber=")
			fmt.Sscanf(v, "%d", &st.Sequence)
		}
		if strings.HasPrefix(line, "timestamp=") {
			v := strings.TrimPrefix(line, "timestamp=")
			st.Timestamp = strings.ReplaceAll(v, `\:`, ":")
		}
	}
	return st, nil
}

// gzipReader wraps a reader with gzip decompression.
func gzipReader(r io.Reader) io.Reader {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return r // not gzip; return as-is
	}
	return gz
}

// fetchDiff retrieves a diff file. It supports the standard http(s) feed and
// file:// URLs (for offline/testing against a local mock feed).
func fetchDiff(rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "file" {
		f, err := os.Open(u.Path)
		if err != nil {
			if os.IsNotExist(err) {
				return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: f}, nil
	}
	return http.Get(rawURL)
}

// replicationURL builds the OSM replication change-file path for a sequence
// number. OSM splits the number into 3-digit groups from the right, then pads
// with leading zero groups so the total is a multiple of 3 (each group is
// zero-padded): 1 -> 000/001, 100 -> 000/100, 1000 -> 001/000, 4913 ->
// 000/004/913, 1234567 -> 001/234/567.
func replicationURL(seq uint64) string {
	n := seq
	var parts []string
	for {
		parts = append([]string{fmt.Sprintf("%03d", n%1000)}, parts...)
		n /= 1000
		if n == 0 {
			break
		}
	}
	// Pad with leading zero groups to a multiple of 3 (and at least 2).
	for len(parts)%3 != 0 {
		parts = append([]string{"000"}, parts...)
	}
	return strings.Join(parts, "/") + ".osc.gz"
}

func main() {
	dbPath := flag.String("db", "data/vic.db", "pipeline DB path")
	base := flag.String("base", "https://download.geofabrik.de/australia-oceania/australia-updates", "OSM replication base URL (default: geofabrik Australia regional feed)")
	load := flag.String("load", "", "path to loadoscdiff binary (default: build it or use go run)")
	max := flag.Int("max", 0, "max diffs to apply in one run (0 = until caught up)")
	flag.Parse()

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// Migrate an older DB to the R2.5 schema (poi_meta + seq/ts on poi) before
	// reading the anchor — a DB materialised before R2.5 lacks poi_meta, and
	// the anchor read would fail. Never destructive.
	if err := schema.MigratePOISchema(db); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	// Read the current anchor (or 0 if poi_meta is empty/first run).
	var seq uint64
	var ts string
	err = db.QueryRow(`SELECT replication_seq, replication_ts FROM poi_meta WHERE id=1`).Scan(&seq, &ts)
	if err == sql.ErrNoRows {
		seq, ts = 0, ""
	} else if err != nil {
		log.Fatalf("read anchor: %v", err)
	}

	// First run (no anchor row): seed from the feed's state.txt so we start at
	// the feed's current point instead of grinding from sequence 1, and
	// persist it to poi_meta so the read next run sees it. The geofabrik
	// sequenceNumber is its own counter (not the global OSM one).
	if seq == 0 {
		st, err := fetchState(*base + "/state.txt")
		if err != nil {
			log.Fatalf("fetch state.txt (seed): %v", err)
		}
		seq = st.Sequence
		ts = st.Timestamp
		if _, err := db.Exec(`INSERT INTO poi_meta(id, replication_seq, replication_ts)
			VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET replication_seq=excluded.replication_seq,
			replication_ts=excluded.replication_ts`, seq, ts); err != nil {
			log.Fatalf("persist seed anchor: %v", err)
		}
		fmt.Printf("seeded anchor from state.txt: seq=%d ts=%s\n", seq, ts)
	}

	applied := 0
	for {
		if *max > 0 && applied >= *max {
			break
		}
		next := seq + 1
		url := *base + "/" + replicationURL(next)
		resp, err := fetchDiff(url)
		if err != nil {
			log.Fatalf("fetch %s: %v", url, err)
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			break // caught up; no newer diff
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Fatalf("fetch %s: status %d", url, resp.StatusCode)
		}

		// Download to a temp file (gzip), then gunzip to a plain .osc —
		// loadoscdiff reads uncompressed OSC XML.
		gzPath := filepath.Join(os.TempDir(), fmt.Sprintf("osc-%d.osc.gz", next))
		f, err := os.Create(gzPath)
		if err != nil {
			log.Fatalf("create temp: %v", err)
		}
		if _, err := io.Copy(f, resp.Body); err != nil {
			f.Close()
			resp.Body.Close()
			log.Fatalf("copy: %v", err)
		}
		f.Close()
		resp.Body.Close()

		oscPath := filepath.Join(os.TempDir(), fmt.Sprintf("osc-%d.osc", next))
		gz, err := os.Open(gzPath)
		if err != nil {
			log.Fatalf("open gz: %v", err)
		}
		out, err := os.Create(oscPath)
		if err != nil {
			gz.Close()
			log.Fatalf("create osc: %v", err)
		}
		if _, err := io.Copy(out, gzipReader(gz)); err != nil {
			gz.Close()
			out.Close()
			log.Fatalf("gunzip: %v", err)
		}
		gz.Close()
		out.Close()
		os.Remove(gzPath)

		// The diff's as-of replication point is next (the file we fetched).
		ts := time.Now().UTC().Format(time.RFC3339)
		cmd := exec.Command(*load, "-db", *dbPath, "-osc", oscPath, "-seq", fmt.Sprintf("%d", next), "-ts", ts)
		comb, err := cmd.CombinedOutput()
		if err != nil {
			os.Remove(oscPath)
			log.Fatalf("loadoscdiff (seq %d): %v\n%s", next, err, comb)
		}
		os.Remove(oscPath)
		fmt.Printf("applied seq %d: %s", next, strings.TrimSpace(string(comb)))
		seq = next
		applied++
	}

	fmt.Printf("applied %d diff(s); anchor now seq=%d\n", applied, seq)
}
