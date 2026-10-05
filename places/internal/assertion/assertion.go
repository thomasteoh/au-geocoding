// Package assertion implements the enrich assertion store (P-D02): append-only
// immutable facts, a derived canonical view, and batch validation/apply. This
// is the "pull a dataset in, update per-record, ad hoc" path. The store never
// mutates a serving dataset — enrichment reaches serving only through a P1
// build (INV-4).
package assertion

import (
	"database/sql"
	"fmt"
	"time"
)

// Schema creates the assertion-store tables. Append-only (INV-4-adjacent: the
// serving dataset is never touched here). WAL + synchronous=NORMAL because
// this is a write-heavy batch pipeline, the opposite access pattern of the
// read-only server.
const Schema = `
CREATE TABLE IF NOT EXISTS sources (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  licence      TEXT NOT NULL,          -- P-D04: no licence, no ingest
  trust_weight REAL NOT NULL DEFAULT 1,
  ingest_method TEXT NOT NULL,
  enabled      INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS assertions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id     TEXT NOT NULL REFERENCES sources(id),
  subject       TEXT NOT NULL,
  predicate     TEXT NOT NULL,
  object        TEXT NOT NULL,         -- JSON-encoded when structured
  observed_at   TEXT NOT NULL,         -- RFC3339; the temporal anchor
  confidence    REAL NOT NULL DEFAULT 1,
  superseded_by INTEGER,               -- set when the same source revises
  retracted_at  TEXT,                  -- set when withdrawn (mark, never delete)
  batch_id      TEXT,                  -- which batch introduced it
  provenance    TEXT NOT NULL DEFAULT ''  -- source URL / rule version, JSON
);
CREATE INDEX IF NOT EXISTS idx_assert_subject ON assertions(subject);
CREATE INDEX IF NOT EXISTS idx_assert_predicate ON assertions(predicate);
CREATE INDEX IF NOT EXISTS idx_assert_source ON assertions(source_id);
CREATE INDEX IF NOT EXISTS idx_assert_observed ON assertions(observed_at);
CREATE TABLE IF NOT EXISTS canonical (
  subject       TEXT NOT NULL,
  predicate     TEXT NOT NULL,
  object        TEXT NOT NULL,
  source_id     TEXT NOT NULL,
  observed_at   TEXT NOT NULL,
  confidence    REAL NOT NULL,
  PRIMARY KEY (subject, predicate)
);
CREATE TABLE IF NOT EXISTS batch_log (
  id        TEXT PRIMARY KEY,          -- the batch id, client-supplied
  source    TEXT NOT NULL,
  version   TEXT NOT NULL,             -- dataset version it came from
  rule      TEXT NOT NULL,             -- ingestion rule version
  applied   INTEGER NOT NULL,
  rejected  INTEGER NOT NULL,
  derived   INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL
);
`

// Assertion is one immutable fact. The object is JSON-encoded when structured;
// observed_at is RFC3339 (the temporal anchor, P-D02).
type Assertion struct {
	Source     string  `json:"source"`
	Subject    string  `json:"subject"`
	Predicate  string  `json:"predicate"`
	Object     string  `json:"object"`
	ObservedAt string  `json:"observed_at"` // RFC3339
	Confidence float64 `json:"confidence"`  // 0..1
	BatchID    string  `json:"batch_id,omitempty"`
	Provenance string  `json:"provenance,omitempty"`
}

// Batch is the input envelope. NDJSON in/out (P6): one assertion per line;
// results stream as they complete and may be out of order; correlate by id.
type Batch struct {
	ID      string      `json:"id"`
	Source  string      `json:"source"`  // must be a registered source
	Version string      `json:"version"` // dataset version the facts came from
	Rule    string      `json:"rule"`    // ingestion rule version
	Items   []Assertion `json:"items"`
}

// Result is one per-assertion outcome, streamed inline.
type Result struct {
	Index  int    `json:"index"`
	ID     string `json:"id,omitempty"`
	Status string `json:"status"` // applied | superseded | retracted | rejected
	Error  string `json:"error,omitempty"`
}

// Open opens the assertion store at path. Creates schema if absent.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("wal: %w", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sync: %w", err)
	}
	if _, err := db.Exec(Schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Store wraps the assertion database.
type Store struct {
	db *sql.DB
}

// Close closes the underlying DB.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for callers that need a transaction.
func (s *Store) DB() *sql.DB { return s.db }

// RegisterSource adds a source to the registry. P-D04: licence is mandatory.
func (s *Store) RegisterSource(id, name, licence, method string, trust float64) error {
	if licence == "" {
		return fmt.Errorf("licence required (P-D04)")
	}
	_, err := s.db.Exec(`INSERT INTO sources(id,name,licence,trust_weight,ingest_method)
		VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,
		licence=excluded.licence, trust_weight=excluded.trust_weight, ingest_method=excluded.ingest_method`,
		id, name, licence, trust, method)
	return err
}

// Validate checks one assertion against the store's rules. Returns a
// human-readable error if the row must be rejected (never silently dropped).
func (s *Store) Validate(a Assertion) error {
	if a.Source == "" {
		return fmt.Errorf("source required")
	}
	if a.Subject == "" {
		return fmt.Errorf("subject required")
	}
	if a.Predicate == "" {
		return fmt.Errorf("predicate required")
	}
	if a.Object == "" {
		return fmt.Errorf("object required")
	}
	if a.ObservedAt == "" {
		return fmt.Errorf("observed_at required")
	}
	if _, err := time.Parse(time.RFC3339, a.ObservedAt); err != nil {
		return fmt.Errorf("observed_at not RFC3339: %v", err)
	}
	if a.Confidence < 0 || a.Confidence > 1 {
		return fmt.Errorf("confidence out of 0..1: %v", a.Confidence)
	}
	// P-D04: the source must be registered and licensed.
	var licence string
	err := s.db.QueryRow(`SELECT licence FROM sources WHERE id=? AND enabled=1`, a.Source).Scan(&licence)
	if err == sql.ErrNoRows {
		return fmt.Errorf("source not registered or disabled: %s", a.Source)
	}
	if err != nil {
		return fmt.Errorf("source lookup: %w", err)
	}
	if licence == "" {
		return fmt.Errorf("source has no licence: %s", a.Source)
	}
	return nil
}

// Apply appends a validated batch atomically per chunk and derives the
// affected records. Returns per-item results and the batch summary.
func (s *Store) Apply(b Batch) ([]Result, BatchSummary, error) {
	if b.ID == "" {
		return nil, BatchSummary{}, fmt.Errorf("batch id required")
	}
	// Reject a duplicate batch id — a batch is idempotent per id.
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM batch_log WHERE id=?`, b.ID).Scan(&n); err == nil && n > 0 {
		return nil, BatchSummary{}, fmt.Errorf("batch %s already applied", b.ID)
	}

	results := make([]Result, len(b.Items))
	applied, rejected := 0, 0

	tx, err := s.db.Begin()
	if err != nil {
		return nil, BatchSummary{}, fmt.Errorf("tx: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339)
	for i, a := range b.Items {
		res := Result{Index: i, ID: a.BatchID}
		if a.BatchID == "" {
			res.ID = ""
		}
		if err := s.Validate(a); err != nil {
			res.Status = "rejected"
			res.Error = err.Error()
			rejected++
			results[i] = res
			continue
		}
		// Append. Revision supersedes: if the same source already asserted this
		// (subject,predicate) with a newer observed_at, mark it superseded.
		var oldID int64
		_ = tx.QueryRow(`SELECT id FROM assertions WHERE source_id=? AND subject=? AND predicate=? AND retracted_at IS NULL
			ORDER BY observed_at DESC LIMIT 1`, a.Source, a.Subject, a.Predicate).Scan(&oldID)
		var id int64
		resInsert, err := tx.Exec(`INSERT INTO assertions(source_id,subject,predicate,object,observed_at,confidence,batch_id,provenance)
			VALUES(?,?,?,?,?,?,?,?)`,
			a.Source, a.Subject, a.Predicate, a.Object, a.ObservedAt, a.Confidence, b.ID, a.Provenance)
		if err != nil {
			res.Status = "rejected"
			res.Error = err.Error()
			rejected++
			results[i] = res
			continue
		}
		id, _ = resInsert.LastInsertId()
		if oldID > 0 {
			// Mark the prior assertion as superseded by the incoming one.
			_, _ = tx.Exec(`UPDATE assertions SET superseded_by=? WHERE id=?`, id, oldID)
		}
		res.Status = "applied"
		applied++
		results[i] = res
	}

	// Derive affected records (subjects touched by this batch). Affected-records-
	// only (E-02 default): full re-derive is a P1 rebuild, not a batch.
	if err := s.Derive(tx, b.Items); err != nil {
		return nil, BatchSummary{}, fmt.Errorf("derive: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, BatchSummary{}, fmt.Errorf("commit: %w", err)
	}

	// Record the batch.
	fin := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO batch_log(id,source,version,rule,applied,rejected,derived,started_at,finished_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, b.ID, b.Source, b.Version, b.Rule, applied, rejected, len(b.Items), now, fin); err != nil {
		return nil, BatchSummary{}, fmt.Errorf("batch log: %w", err)
	}

	return results, BatchSummary{Applied: applied, Rejected: rejected, Derived: len(b.Items), ID: b.ID}, nil
}

// BatchSummary is the change audit: what changed, which source, how many rows.
type BatchSummary struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Applied  int    `json:"applied"`
	Rejected int    `json:"rejected"`
	Derived  int    `json:"derived"`
}

// CanonicalRows dumps the derived canonical view as (subject, predicate,
// object) rows. Used by the P1 build to overlay enrichment onto a freshly
// materialised serving table (processes.md: enrichment reaches serving only
// through P1).
func (s *Store) CanonicalRows() ([]CanonicalRow, error) {
	rows, err := s.db.Query(`SELECT subject, predicate, object, source_id, observed_at, confidence
		FROM canonical ORDER BY subject, predicate`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CanonicalRow
	for rows.Next() {
		var c CanonicalRow
		if err := rows.Scan(&c.Subject, &c.Predicate, &c.Object, &c.Source, &c.ObservedAt, &c.Confidence); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CanonicalRow is one derived fact from the canonical view.
type CanonicalRow struct {
	Subject    string  `json:"subject"`
	Predicate  string  `json:"predicate"`
	Object     string  `json:"object"`
	Source     string  `json:"source"`
	ObservedAt string  `json:"observed_at"`
	Confidence float64 `json:"confidence"`
}

// DeriveSubject re-derives the canonical row for a single subject from all
// live assertions. This is the repair/refresh step for ad hoc corrections
// (P-D02): after a retract or a high-trust correction, recompute the derived
// value for just that subject.
func (s *Store) DeriveSubject(subject string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.deriveSubject(tx, subject); err != nil {
		return err
	}
	return tx.Commit()
}

// Derive recomputes the canonical row for each subject in items. Highest score
// (trust_weight × confidence × recency_decay(observed_at)) wins per field;
// ties break by source priority. Conflicting high-trust values are flagged,
// never silently resolved (archive/architecture.md).
func (s *Store) Derive(tx *sql.Tx, items []Assertion) error {
	subjects := map[string]bool{}
	for _, a := range items {
		subjects[a.Subject] = true
	}
	for subj := range subjects {
		if err := s.deriveSubject(tx, subj); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) deriveSubject(tx *sql.Tx, subject string) error {
	// Latest non-retracted, non-superseded assertion per predicate. We rank by
	// recency-decayed trust score, then latest observed_at.
	rows, err := tx.Query(`
		SELECT predicate, object, source_id, observed_at, confidence,
		       (SELECT trust_weight FROM sources WHERE id=a.source_id) AS trust
		FROM assertions a
		WHERE subject=? AND retracted_at IS NULL AND superseded_by IS NULL
		ORDER BY predicate`,
		subject)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Group per predicate and pick the highest score.
	best := map[string]struct {
		object, source, observed string
		score                    float64
	}{}
	for rows.Next() {
		var predicate, object, source, observed string
		var confidence, trust float64
		if err := rows.Scan(&predicate, &object, &source, &observed, &confidence, &trust); err != nil {
			return err
		}
		recency := recencyDecay(observed)
		score := trust * confidence * recency
		cur, ok := best[predicate]
		if !ok || score > cur.score || (score == cur.score && observed > cur.observed) {
			best[predicate] = struct {
				object, source, observed string
				score                    float64
			}{object, source, observed, score}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for predicate, b := range best {
		if _, err := tx.Exec(`INSERT INTO canonical(subject,predicate,object,source_id,observed_at,confidence)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(subject,predicate) DO UPDATE SET object=excluded.object,
			source_id=excluded.source_id, observed_at=excluded.observed_at, confidence=excluded.confidence`,
			subject, predicate, b.object, b.source, b.observed, b.score); err != nil {
			return err
		}
	}
	// Delete canonical rows for predicates that no longer have a live
	// assertion (e.g. after a retract removed the last one). Without this the
	// derived view keeps a stale value for a now-empty predicate.
	if _, err := tx.Exec(`DELETE FROM canonical WHERE subject=? AND predicate NOT IN (SELECT predicate FROM assertions WHERE subject=? AND retracted_at IS NULL AND superseded_by IS NULL)`, subject, subject); err != nil {
		return err
	}
	return nil
}

// recencyDecay is a monotonic 0..1 factor: the older the observation, the lower
// the weight. Half-life 180 days (aligns with the G-NAF staleness ceiling).
func recencyDecay(observed string) float64 {
	t, err := time.Parse(time.RFC3339, observed)
	if err != nil {
		return 1
	}
	age := time.Since(t).Hours() / 24
	halflife := 180.0
	return 0.5 * (1 + 1/(1+age/halflife)) // 1.0 at age 0, -> 0.5 as age grows
}

// Retract marks an assertion withdrawn (never deleted). Returns how many were
// marked. Re-derive after.
func (s *Store) Retract(source, subject, predicate string) (int, error) {
	res, err := s.db.Exec(`UPDATE assertions SET retracted_at=? WHERE source_id=? AND subject=? AND predicate=? AND retracted_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), source, subject, predicate)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// PointInTime answers "what was this subject at time t": the latest
// non-retracted assertion per predicate with observed_at <= t. The append-only
// log is the temporal record.
func (s *Store) PointInTime(subject, at string) (map[string]string, error) {
	out := map[string]string{}
	rows, err := s.db.Query(`
		SELECT predicate, object FROM assertions
		WHERE subject=? AND retracted_at IS NULL AND observed_at<=?
		ORDER BY observed_at DESC`,
		subject, at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var predicate, object string
		if err := rows.Scan(&predicate, &object); err != nil {
			return nil, err
		}
		if !seen[predicate] {
			out[predicate] = object
			seen[predicate] = true
		}
	}
	return out, rows.Err()
}

// RegionDiff is the change report for a set of subjects in a time window:
// which subjects gained or lost a predicate value.
type RegionDiff struct {
	Changed []SubjectChange `json:"changed"`
}

type SubjectChange struct {
	Subject string `json:"subject"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}
