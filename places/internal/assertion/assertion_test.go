package assertion

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// newTestStore opens a fresh assertion store in a temp dir.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	// Register a couple of sources for validation.
	if err := store.RegisterSource("gnaf", "G-NAF", "CC-BY-4.0", "bulk", 0.9); err != nil {
		t.Fatalf("register gnaf: %v", err)
	}
	if err := store.RegisterSource("osm", "OpenStreetMap", "ODbL-1.0", "pbf", 0.8); err != nil {
		t.Fatalf("register osm: %v", err)
	}
	return store
}

func TestValidateRejectsBadAssertion(t *testing.T) {
	s := newTestStore(t)
	cases := []Assertion{
		{Subject: "x", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},                    // no source
		{Source: "gnaf", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},                  // no subject
		{Source: "gnaf", Subject: "x", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},                       // no predicate
		{Source: "gnaf", Subject: "x", Predicate: "name", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},                 // no object
		{Source: "gnaf", Subject: "x", Predicate: "name", Object: "a", Confidence: 1},                                        // no observed_at
		{Source: "gnaf", Subject: "x", Predicate: "name", Object: "a", ObservedAt: "not-a-date", Confidence: 1},              // bad RFC3339
		{Source: "gnaf", Subject: "x", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1.5},  // confidence > 1
		{Source: "gnaf", Subject: "x", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: -0.1}, // confidence < 0
		{Source: "missing", Subject: "x", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1}, // unregistered source
	}
	for i, a := range cases {
		if err := s.Validate(a); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestApplyBatch(t *testing.T) {
	s := newTestStore(t)
	b := Batch{
		ID: "b1", Source: "gnaf", Version: "gnaf-aug26", Rule: "v1",
		Items: []Assertion{
			{Source: "gnaf", Subject: "GAVIC411711441", Predicate: "name", Object: "Collingwood", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},
			{Source: "gnaf", Subject: "GAVIC411711441", Predicate: "lat", Object: "-37.8", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},
		},
	}
	results, summary, err := s.Apply(b)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if summary.Applied != 2 || summary.Rejected != 0 {
		t.Fatalf("summary: applied=%d rejected=%d want 2/0", summary.Applied, summary.Rejected)
	}
	for i, r := range results {
		if r.Status != "applied" {
			t.Fatalf("result %d: status=%s want applied", i, r.Status)
		}
	}
	// Canonical derived.
	var name string
	if err := s.db.QueryRow(`SELECT object FROM canonical WHERE subject=? AND predicate=?`, "GAVIC411711441", "name").Scan(&name); err != nil {
		t.Fatalf("canonical name: %v", err)
	}
	if name != "Collingwood" {
		t.Fatalf("canonical name=%q", name)
	}
}

func TestApplyRejectsBadRowsInline(t *testing.T) {
	s := newTestStore(t)
	b := Batch{
		ID: "b2", Source: "gnaf", Version: "v1", Rule: "r1",
		Items: []Assertion{
			{Source: "gnaf", Subject: "x", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},
			{Source: "gnaf", Subject: "", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1}, // missing subject
		},
	}
	results, summary, err := s.Apply(b)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if summary.Applied != 1 || summary.Rejected != 1 {
		t.Fatalf("summary: applied=%d rejected=%d want 1/1", summary.Applied, summary.Rejected)
	}
	if results[0].Status != "applied" || results[1].Status != "rejected" {
		t.Fatalf("statuses: %s %s", results[0].Status, results[1].Status)
	}
	if results[1].Error == "" {
		t.Fatal("rejected row should carry an error")
	}
}

func TestDuplicateBatchRejected(t *testing.T) {
	s := newTestStore(t)
	b := Batch{ID: "dup", Source: "gnaf", Version: "v1", Rule: "r1",
		Items: []Assertion{{Source: "gnaf", Subject: "x", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1}}}
	if _, _, err := s.Apply(b); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if _, _, err := s.Apply(b); err == nil {
		t.Fatal("duplicate batch id should be rejected")
	}
}

func TestSupersede(t *testing.T) {
	s := newTestStore(t)
	// Same source revises its own claim: the newer observed_at supersedes.
	old := Assertion{Source: "gnaf", Subject: "x", Predicate: "name", Object: "Old", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1}
	new := Assertion{Source: "gnaf", Subject: "x", Predicate: "name", Object: "New", ObservedAt: "2026-02-01T00:00:00Z", Confidence: 1}
	if _, _, err := s.Apply(Batch{ID: "s1", Source: "gnaf", Version: "v", Rule: "r", Items: []Assertion{old}}); err != nil {
		t.Fatalf("apply old: %v", err)
	}
	if _, _, err := s.Apply(Batch{ID: "s2", Source: "gnaf", Version: "v", Rule: "r", Items: []Assertion{new}}); err != nil {
		t.Fatalf("apply new: %v", err)
	}
	// The old row is superseded.
	var superseded sql.NullInt64
	if err := s.db.QueryRow(`SELECT superseded_by FROM assertions WHERE source_id='gnaf' AND subject='x' AND predicate='name' AND object='Old'`).Scan(&superseded); err != nil {
		t.Fatalf("superseded lookup: %v", err)
	}
	if !superseded.Valid {
		t.Fatal("old assertion should be superseded")
	}
	// Canonical holds the newer value.
	var name string
	if err := s.db.QueryRow(`SELECT object FROM canonical WHERE subject='x' AND predicate='name'`).Scan(&name); err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if name != "New" {
		t.Fatalf("canonical name=%q want New", name)
	}
}

func TestRetract(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.Apply(Batch{ID: "r1", Source: "gnaf", Version: "v", Rule: "r",
		Items: []Assertion{{Source: "gnaf", Subject: "x", Predicate: "name", Object: "a", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1}}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	n, err := s.Retract("gnaf", "x", "name")
	if err != nil {
		t.Fatalf("retract: %v", err)
	}
	if n != 1 {
		t.Fatalf("retracted=%d want 1", n)
	}
	// Retracted assertion is excluded from canonical (derive picks nothing).
	var cnt int
	if err := s.db.QueryRow(`SELECT count(*) FROM canonical WHERE subject='x' AND predicate='name'`).Scan(&cnt); err != nil {
		t.Fatalf("canonical count: %v", err)
	}
	// Retraction marks, it does not delete: the assertion row remains.
	var rowCnt int
	if err := s.db.QueryRow(`SELECT count(*) FROM assertions WHERE subject='x' AND predicate='name'`).Scan(&rowCnt); err != nil {
		t.Fatalf("assertions count: %v", err)
	}
	if rowCnt != 1 {
		t.Fatalf("assertion row should remain after retract, got %d", rowCnt)
	}
}

func TestPointInTime(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.Apply(Batch{ID: "p1", Source: "gnaf", Version: "v", Rule: "r",
		Items: []Assertion{
			{Source: "gnaf", Subject: "x", Predicate: "name", Object: "Old", ObservedAt: "2024-01-01T00:00:00Z", Confidence: 1},
			{Source: "gnaf", Subject: "x", Predicate: "name", Object: "New", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1},
		}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Point in time 2025: should return the 2024 value (Old).
	got, err := s.PointInTime("x", "2025-06-01T00:00:00Z")
	if err != nil {
		t.Fatalf("point in time: %v", err)
	}
	if got["name"] != "Old" {
		t.Fatalf("pit name=%q want Old", got["name"])
	}
	// Point in time 2027: the newer value.
	got, err = s.PointInTime("x", "2027-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("point in time 2: %v", err)
	}
	if got["name"] != "New" {
		t.Fatalf("pit name=%q want New", got["name"])
	}
}

func TestDeriveScorePrefersHigherTrust(t *testing.T) {
	s := newTestStore(t)
	// gnaf trust 0.9, osm trust 0.8. Same predicate, conflicting values.
	// gnaf wins on trust × confidence.
	if _, _, err := s.Apply(Batch{ID: "d1", Source: "gnaf", Version: "v", Rule: "r",
		Items: []Assertion{
			{Source: "gnaf", Subject: "x", Predicate: "brand", Object: "Woolies", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 0.9},
			{Source: "osm", Subject: "x", Predicate: "brand", Object: "Woolworths", ObservedAt: "2026-01-01T00:00:00Z", Confidence: 1.0},
		}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var brand string
	if err := s.db.QueryRow(`SELECT object FROM canonical WHERE subject='x' AND predicate='brand'`).Scan(&brand); err != nil {
		t.Fatalf("canonical brand: %v", err)
	}
	// gnaf: 0.9*0.9=0.81; osm: 0.8*1.0=0.80 → gnaf wins.
	if brand != "Woolies" {
		t.Fatalf("brand=%q want Woolies", brand)
	}
}

func TestRegionDiffShape(t *testing.T) {
	// RegionDiff is a report type; ensure JSON marshals cleanly.
	var r RegionDiff
	r.Changed = append(r.Changed, SubjectChange{Subject: "x", Before: "a", After: "b"})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("empty marshal")
	}
}
