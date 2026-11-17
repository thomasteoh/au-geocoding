// activate implements P3 — the versioned swap. Given a new versioned dataset
// file that has passed P1 stage-5 verify, it signals the running server to
// open the new file and route new requests to it. In-flight requests finish
// against the old pool and report the old DatasetVersion (INV-5: skew becomes
// visible). The previous file is retained for rollback.
//
// R3.1: activation never mutates a file in place. R3.5: failure to open the
// new file leaves the old pool serving and raises an alert.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	newDB := flag.String("db", "data/vic.db.new", "new versioned dataset to activate")
	version := flag.String("version", "", "expected dataset version (optional; the server checks it against the dataset's own)")
	ctrlURL := flag.String("ctrl", "http://127.0.0.1:8080/ctrl/activate", "control endpoint")
	flag.Parse()

	// R3.2: DatasetVersion is read from the open handle, never by stat'ing a
	// path. Open the new file read-only and read the version from a query.
	db, err := sql.Open("sqlite", "file:"+*newDB+"?mode=ro")
	if err != nil {
		log.Fatalf("open new dataset: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA query_only=ON`); err != nil {
		log.Fatalf("query_only: %v", err)
	}
	// Confirm it's a valid dataset.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM address`).Scan(&n); err != nil {
		log.Fatalf("new dataset has no address table: %v", err)
	}
	// The dataset carries its own version (buildaddr -version); the server
	// rejects an activation whose requested version differs, so check here
	// first and fail with a clear message.
	var have string
	if err := db.QueryRow(`SELECT dataset_version FROM address LIMIT 1`).Scan(&have); err != nil {
		log.Fatalf("new dataset has no version: %v", err)
	}
	if *version != "" && *version != have {
		log.Fatalf("dataset version is %q, not %q", have, *version)
	}
	fmt.Printf("new dataset opened: address rows=%d version=%s\n", n, have)

	// Signal the running server. The control endpoint swaps the pool. The
	// server must have the new file already on disk (it is, since we opened
	// it). The server opens its own handle — we only signal.
	payload, err := json.Marshal(map[string]string{"db": *newDB, "version": have})
	if err != nil {
		log.Fatalf("encode request: %v", err)
	}
	body := string(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *ctrlURL, strings.NewReader(body))
	if err != nil {
		log.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The control endpoint is gated: it requires the AUGEO_CTRL_TOKEN. The tool
	// reads the token from the env var (same one the server uses) — never a flag
	// (so it can't leak into shell history) — and sends it as X-Augeo-Ctrl-Token.
	if tok := os.Getenv("AUGEO_CTRL_TOKEN"); tok != "" {
		req.Header.Set("X-Augeo-Ctrl-Token", tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("signal server: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("server rejected activation: %d", resp.StatusCode)
	}
	fmt.Println("activation signalled; server should now route to new dataset")
}
