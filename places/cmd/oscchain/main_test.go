package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStateURLSitsBesideTheDiff(t *testing.T) {
	if got := replicationURL(4913); got != "000/004/913.osc.gz" {
		t.Errorf("replicationURL = %q", got)
	}
	if got := stateURL(4913); got != "000/004/913.state.txt" {
		t.Errorf("stateURL = %q", got)
	}
}

// The per-diff state file supplies the as-of timestamp; a missing one is the
// not-yet-published signal, distinct from a feed error.
func TestFetchStateParsesAndReportsMissing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "913.state.txt")
	if err := os.WriteFile(p, []byte("#Mon Nov 16\nsequenceNumber=4913\ntimestamp=2026-11-16T20\\:21\\:00Z\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := fetchState("file://" + p)
	if err != nil || st.Sequence != 4913 || st.Timestamp != "2026-11-16T20:21:00Z" {
		t.Fatalf("fetchState = %+v, %v", st, err)
	}
	if _, err := fetchState("file://" + filepath.Join(dir, "missing.state.txt")); !errors.Is(err, errNotFound) {
		t.Errorf("missing state: err = %v, want errNotFound", err)
	}
}

func TestFeedClientHasTimeout(t *testing.T) {
	if httpClient.Timeout <= 0 {
		t.Error("feed client has no timeout")
	}
}
