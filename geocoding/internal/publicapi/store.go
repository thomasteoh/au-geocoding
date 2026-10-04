// Package publicapi implements the public API surface: key auth (D-006),
// token-bucket rate limiting, per-row quota accounting (D-034), the app.db
// service tables (api_keys, usage, request_log) and the abuse guards from
// security.md T1–T7. It is deliberately separate from the geocoding DBs — app.db
// is mutable service state, never mixed into the read-only geocoding DBs.
package publicapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Errors for the public API. Uniform responses for unknown vs revoked vs
// over-quota keys (T6) — never confirm which keys exist.
var (
	ErrInvalidKey    = errors.New("invalid api key")
	ErrQuotaExceeded = errors.New("daily quota exceeded")
	ErrRateLimited   = errors.New("rate limited")
)

// Tier is a quota tier. Anonymous and keyed access get separate ceilings (T1).
type Tier int

const (
	TierAnonymous Tier = iota
	TierDemo
	TierStandard
	TierBatch
)

// Quota is the daily result-row ceiling per tier (D-034: per row, not request).
var TierQuota = map[Tier]int64{
	TierAnonymous: 100,
	TierDemo:      1000,
	TierStandard:  10000,
	TierBatch:     100000,
}

// QuotaTier returns the tier for a key's quota_tier string.
func QuotaTier(s string) Tier {
	switch strings.ToLower(s) {
	case "anonymous":
		return TierAnonymous
	case "demo":
		return TierDemo
	case "standard":
		return TierStandard
	case "batch":
		return TierBatch
	default:
		return TierDemo
	}
}

// Pepper is the server-side secret mixed into key hashes (T6). Generated at
// boot; never persisted, never logged.
type Pepper [32]byte

// GeneratePepper creates a fresh pepper at startup.
func GeneratePepper() Pepper {
	var p Pepper
	if _, err := rand.Read(p[:]); err != nil {
		panic(err)
	}
	return p
}

// HashKey computes SHA-256(key ‖ pepper), the stored form (T6: never the raw key).
func HashKey(key string, pepper Pepper) [32]byte {
	h := sha256.New()
	h.Write([]byte(key))
	h.Write(pepper[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// KeyPrefix is the short non-secret prefix used for O(1) index lookup (T6).
func KeyPrefix(key string) string {
	if len(key) < 8 {
		return key
	}
	return key[:8]
}

// Key is the in-memory form of an api_keys row.
type Key struct {
	ID      int64
	Prefix  string
	Hash    [32]byte
	Label   string
	Tier    Tier
	Enabled bool
	Scopes  []string
	Created time.Time
	Revoked *time.Time
}

// Store is the app.db service-state store. It owns api_keys, usage and
// request_log, in a SQLite file separate from the geocoding DBs.
type Store struct {
	db     *sql.DB
	pepper Pepper
	mu     sync.Mutex
	keys   map[string]Key // prefix → Key (non-secret index)

	// AnonDaily tracks anonymous daily usage per IP, in memory only (D-026:
	// per-IP quota is per-replica and resets on restart — accepted weakness,
	// capped by the global ceiling). Never persisted, never logged.
	anonMu  sync.Mutex
	anonDay string
	anonIPs map[string]int64 // ip → rows consumed today
}

// Open opens app.db (creating the schema on first run) and loads keys. The
// pepper is persisted in app.db so every process that hashes keys uses the same
// pepper — a per-process random pepper would make keys issued by keygen
// unverifiable by the server.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &Store{
		db:      db,
		pepper:  GeneratePepper(),
		keys:    make(map[string]Key),
		anonIPs: make(map[string]int64),
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	// Load or create a persisted pepper (32 bytes hex).
	if err := s.loadOrCreatePepper(); err != nil {
		return nil, err
	}
	if err := s.loadKeys(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadOrCreatePepper reads the pepper from app.db, generating and persisting it
// on first run. The pepper is the server-side secret mixed into key hashes (T6).
func (s *Store) loadOrCreatePepper() error {
	var hexStr string
	err := s.db.QueryRow(`SELECT value FROM pepper WHERE id=1`).Scan(&hexStr)
	if err == sql.ErrNoRows {
		// First run: generate and persist.
		p := GeneratePepper()
		hexStr = hex.EncodeToString(p[:])
		if _, err := s.db.Exec(`INSERT INTO pepper(id, value) VALUES (1, ?)`, hexStr); err != nil {
			return fmt.Errorf("persist pepper: %w", err)
		}
		s.pepper = p
		return nil
	}
	if err != nil {
		return fmt.Errorf("read pepper: %w", err)
	}
	// Decode persisted pepper.
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("decode pepper: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("pepper length %d != 32", len(b))
	}
	copy(s.pepper[:], b)
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS pepper (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			prefix TEXT NOT NULL,
			hash BLOB NOT NULL,
			label TEXT NOT NULL,
			quota_tier TEXT NOT NULL DEFAULT 'demo',
			enabled INTEGER NOT NULL DEFAULT 1,
			scopes TEXT NOT NULL DEFAULT '',
			created TEXT NOT NULL,
			revoked TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS usage (
			key_id INTEGER NOT NULL,
			day TEXT NOT NULL,
			rows INTEGER NOT NULL DEFAULT 0,
			llm_calls INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (key_id, day)
		)`,
		`CREATE TABLE IF NOT EXISTS request_log (
			ts TEXT NOT NULL,
			key_id INTEGER,
			endpoint TEXT NOT NULL,
			status INTEGER NOT NULL,
			latency_ms INTEGER NOT NULL,
			result_count INTEGER NOT NULL,
			strategy TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// loadKeys reads api_keys into the in-memory prefix index.
func (s *Store) loadKeys() error {
	rows, err := s.db.Query(`SELECT id, prefix, hash, label, quota_tier, enabled, scopes, created, revoked FROM api_keys`)
	if err != nil {
		return err
	}
	defer rows.Close()
	s.keys = make(map[string]Key)
	for rows.Next() {
		var k Key
		var hash []byte
		var created, revoked sql.NullString
		var enabled int
		var scopes string
		var tierStr string
		if err := rows.Scan(&k.ID, &k.Prefix, &hash, &k.Label, &tierStr, &enabled, &scopes, &created, &revoked); err != nil {
			return err
		}
		k.Tier = QuotaTier(tierStr)
		copy(k.Hash[:], hash)
		k.Enabled = enabled != 0
		if created.Valid {
			k.Created, _ = time.Parse(time.RFC3339, created.String)
		}
		if revoked.Valid {
			t, _ := time.Parse(time.RFC3339, revoked.String)
			k.Revoked = &t
		}
		k.Scopes = strings.Fields(scopes)
		s.keys[k.Prefix] = k
	}
	return rows.Err()
}

// Authenticate resolves a key string to a Key, using the non-secret prefix for
// O(1) lookup then constant-time compare of the hash (T6). Unknown, revoked,
// disabled and over-quota keys all return ErrInvalidKey — uniform (T6).
func (s *Store) Authenticate(keyStr string) (Key, error) {
	prefix := KeyPrefix(keyStr)
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[prefix]
	if !ok {
		return Key{}, ErrInvalidKey
	}
	hash := HashKey(keyStr, s.pepper)
	if subtle.ConstantTimeCompare(hash[:], k.Hash[:]) != 1 {
		return Key{}, ErrInvalidKey
	}
	if !k.Enabled || k.Revoked != nil {
		return Key{}, ErrInvalidKey
	}
	return k, nil
}

// IssueKey creates a new key. The raw key is returned exactly once and never
// stored or logged (T6).
func (s *Store) IssueKey(label string, tier Tier, scopes []string) (id int64, raw string, err error) {
	raw = newKeyString()
	prefix := KeyPrefix(raw)
	hash := HashKey(raw, s.pepper)
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO api_keys(prefix, hash, label, quota_tier, enabled, scopes, created)
		VALUES (?, ?, ?, ?, 1, ?, ?)`,
		prefix, hash[:], label, tierName(tier), strings.Join(scopes, " "), now)
	if err != nil {
		return 0, "", err
	}
	id, _ = res.LastInsertId()
	s.mu.Lock()
	s.keys[prefix] = Key{ID: id, Prefix: prefix, Hash: hash, Label: label, Tier: tier, Enabled: true, Scopes: scopes, Created: time.Now().UTC()}
	s.mu.Unlock()
	return id, raw, nil
}

// Revoke disables a key. The in-memory index is updated immediately so a
// revoked key stops working without a restart (T8 local-mode caveat: in
// single-instance mode this is safe; at N>1 the cluster backend is required).
func (s *Store) Revoke(id int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`UPDATE api_keys SET enabled=0, revoked=? WHERE id=?`, now, id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, k := range s.keys {
		if k.ID == id {
			t := time.Now().UTC()
			k.Enabled = false
			k.Revoked = &t
			s.keys[p] = k
		}
	}
	return nil
}

// ChargeRows accounts for result rows consumed by a request (D-034). Returns
// false when the tier's daily ceiling would be exceeded.
func (s *Store) ChargeRows(keyID int64, tier Tier, rows int64) (bool, error) {
	if tier == TierAnonymous {
		// Anonymous has no key — charged separately via the IP limiter.
		return true, nil
	}
	day := time.Now().UTC().Format("2006-01-02")
	quota := TierQuota[tier]
	s.mu.Lock()
	defer s.mu.Unlock()
	// Read-modify-write on usage. Fail closed if the store is unreachable (T8).
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var cur int64
	if err := tx.QueryRow(`SELECT rows FROM usage WHERE key_id=? AND day=?`, keyID, day).Scan(&cur); err != nil {
		if err == sql.ErrNoRows {
			cur = 0
		} else {
			return false, err
		}
	}
	if cur+rows > quota {
		return false, ErrQuotaExceeded
	}
	if _, err := tx.Exec(`INSERT INTO usage(key_id, day, rows) VALUES (?,?,?)
		ON CONFLICT(key_id, day) DO UPDATE SET rows=rows+excluded.rows`, keyID, day, rows); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ChargeAnonDaily accounts for anonymous result rows consumed today, per IP
// (D-026: per-IP quota plus a global ceiling). In memory only — resets on
// restart and is per-replica; the global ceiling bounds the worst case.
// Returns false when the IP's daily ceiling or the global ceiling is exceeded.
func (s *Store) ChargeAnonDaily(ip string, rows int64, perIP, global int64) (bool, error) {
	if perIP <= 0 {
		return true, nil // no anonymous daily ceiling configured
	}
	day := time.Now().UTC().Format("2006-01-02")
	s.anonMu.Lock()
	defer s.anonMu.Unlock()
	// Roll the day at midnight.
	if s.anonDay != day {
		s.anonDay = day
		s.anonIPs = make(map[string]int64)
	}
	cur := s.anonIPs[ip]
	if cur+rows > perIP {
		return false, ErrQuotaExceeded
	}
	// Global ceiling: sum over all IPs.
	var total int64
	for _, v := range s.anonIPs {
		total += v
	}
	if global > 0 && total+rows > global {
		return false, ErrQuotaExceeded
	}
	s.anonIPs[ip] = cur + rows
	return true, nil
}

// LogRequest writes one request_log row (T9: no query text, no result contents).
func (s *Store) LogRequest(keyID int64, endpoint string, status int, latencyMS int64, resultCount int, strategy string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO request_log(ts, key_id, endpoint, status, latency_ms, result_count, strategy)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, ts, keyID, endpoint, status, latencyMS, resultCount, strategy)
	return err
}

// tokenBucket is a per-key token bucket (D-006). Tokens refill continuously;
// a burst up to the bucket size is allowed, then the steady rate.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
	used   time.Time // last touch for LRU eviction
}

// newTokenBucket creates a bucket with the given per-second rate and burst.
func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: time.Now(), used: time.Now()}
}

// Allow consumes one token. Returns false when the bucket is empty.
func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(b.tokens+elapsed*b.rate, b.burst)
	b.last = now
	b.used = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RateLimiter holds per-key token buckets.
type RateLimiter struct {
	mu      sync.Mutex
	keys    map[string]*tokenBucket
	rate    float64
	burst   float64
	maxKeys int
}

// NewRateLimiter creates a limiter with per-key buckets at rate/s and burst.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return &RateLimiter{
		keys:    make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
		maxKeys: 100000,
	}
}

// Allow consumes one token for the key (or IP for anonymous). When the key map
// exceeds maxKeys it evicts the least-recently-used bucket — prevents the map
// growing unboundedly with every unique IP/key (memory exhaustion).
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.keys[key]
	if !ok {
		// Evict LRU if at cap.
		if r.maxKeys > 0 && len(r.keys) >= r.maxKeys {
			var oldestKey string
			var oldest time.Time
			for k, b := range r.keys {
				if oldest.IsZero() || b.used.Before(oldest) {
					oldest = b.used
					oldestKey = k
				}
			}
			if oldestKey != "" {
				delete(r.keys, oldestKey)
			}
		}
		b = newTokenBucket(r.rate, r.burst)
		r.keys[key] = b
	}
	return b.Allow()
}

func tierName(t Tier) string {
	switch t {
	case TierAnonymous:
		return "anonymous"
	case TierDemo:
		return "demo"
	case TierStandard:
		return "standard"
	case TierBatch:
		return "batch"
	default:
		return "demo"
	}
}

func newKeyString() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// min is the Go 1.21+ builtin; keep a local for safety.
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
