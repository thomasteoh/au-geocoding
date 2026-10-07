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
	"strconv"
	"strings"
	"sync"
	"time"

	"augeocoding/internal/appdb"
)

// Errors for the public API. Uniform responses for unknown vs revoked vs
// over-quota keys (T6) — never confirm which keys exist.
var (
	ErrInvalidKey    = errors.New("invalid api key")
	ErrQuotaExceeded = errors.New("daily quota exceeded")
	ErrRateLimited   = errors.New("rate limited")
	ErrNotFound      = errors.New("not found")
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
	// OrgID is set for keys issued in the console; 0 for operator keys from
	// keygen. CreatedBy is the issuing user. Expires is optional.
	OrgID     int64
	CreatedBy int64
	Expires   *time.Time
}

// Principal is whoever a public API request is accounted to: an operator
// key, an org (console keys and JWT callers share the org's quota, so
// minting more credentials never multiplies it, T1) or an anonymous IP.
type Principal struct {
	Kind   string // "anonymous", "key", "jwt"
	KeyID  int64  // request_log key_id; 0 for jwt/anonymous
	OrgID  int64
	Tier   Tier
	Scopes []string
	// RateKey is the token-bucket key; UsageKey the daily quota row.
	RateKey  string
	UsageKey string
	// Subject identifies a JWT caller ("jwt:<issuer id>:<sub>").
	Subject string
}

// Anonymous reports whether the principal is the anonymous tier.
func (p Principal) Anonymous() bool { return p.Kind == "anonymous" }

// KeyPrincipal builds the principal for an authenticated key.
func KeyPrincipal(k Key) Principal {
	p := Principal{Kind: "key", KeyID: k.ID, OrgID: k.OrgID, Tier: k.Tier, Scopes: k.Scopes, RateKey: "key:" + strconv.FormatInt(k.ID, 10)}
	if k.OrgID != 0 {
		p.UsageKey = OrgUsageKey(k.OrgID)
	} else {
		p.UsageKey = "key:" + strconv.FormatInt(k.ID, 10)
	}
	return p
}

// OrgUsageKey is the daily quota row shared by an org's keys and JWT callers.
func OrgUsageKey(orgID int64) string { return "org:" + strconv.FormatInt(orgID, 10) }

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
	db, err := appdb.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := New(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// New builds the store on an open app.db handle shared with other stores.
func New(db *sql.DB) (*Store, error) {
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
		// Quota rows keyed by principal ("key:<id>" or "org:<id>"). The old
		// per-key usage table is copied in once and then left alone.
		`CREATE TABLE IF NOT EXISTS usage_principal (
			principal TEXT NOT NULL,
			day TEXT NOT NULL,
			rows INTEGER NOT NULL DEFAULT 0,
			llm_calls INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (principal, day)
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// Columns added for console-issued keys and JWT callers.
	for _, c := range []struct{ table, col, def string }{
		{"api_keys", "org_id", "INTEGER"},
		{"api_keys", "created_by", "INTEGER"},
		{"api_keys", "expires", "TEXT"},
		{"request_log", "principal", "TEXT"},
	} {
		if err := addColumn(s.db, c.table, c.col, c.def); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id)`); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	var copied int
	s.db.QueryRow(`SELECT COUNT(*) FROM usage_principal`).Scan(&copied)
	if copied == 0 {
		if _, err := s.db.Exec(`INSERT OR IGNORE INTO usage_principal(principal, day, rows, llm_calls)
			SELECT 'key:' || key_id, day, rows, llm_calls FROM usage`); err != nil {
			return fmt.Errorf("migrate usage: %w", err)
		}
	}
	return nil
}

func addColumn(db *sql.DB, table, col, def string) error {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == col {
			return nil
		}
	}
	rows.Close()
	if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, col, def)); err != nil {
		return fmt.Errorf("migrate %s.%s: %w", table, col, err)
	}
	return nil
}

// loadKeys reads api_keys into the in-memory prefix index.
func (s *Store) loadKeys() error {
	rows, err := s.db.Query(`SELECT ` + keyCols + ` FROM api_keys`)
	if err != nil {
		return err
	}
	defer rows.Close()
	keys := make(map[string]Key)
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return err
		}
		keys[k.Prefix] = k
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return nil
}

const keyCols = `id, prefix, hash, label, quota_tier, enabled, scopes, created, revoked, COALESCE(org_id,0), COALESCE(created_by,0), expires`

func scanKey(sc interface{ Scan(...any) error }) (Key, error) {
	var k Key
	var hash []byte
	var created, revoked, expires sql.NullString
	var enabled int
	var scopes string
	var tierStr string
	if err := sc.Scan(&k.ID, &k.Prefix, &hash, &k.Label, &tierStr, &enabled, &scopes, &created, &revoked, &k.OrgID, &k.CreatedBy, &expires); err != nil {
		return k, err
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
	if expires.Valid && expires.String != "" {
		t, _ := time.Parse(time.RFC3339, expires.String)
		k.Expires = &t
	}
	k.Scopes = strings.Fields(scopes)
	return k, nil
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
	if k.Expires != nil && !time.Now().Before(*k.Expires) {
		return Key{}, ErrInvalidKey
	}
	return k, nil
}

// IssueKey creates a new key. The raw key is returned exactly once and never
// stored or logged (T6).
func (s *Store) IssueKey(label string, tier Tier, scopes []string) (id int64, raw string, err error) {
	k, raw, err := s.IssueKeyWith(IssueOptions{Label: label, Tier: tier, Scopes: scopes})
	return k.ID, raw, err
}

// IssueOptions describes a key to issue.
type IssueOptions struct {
	Label     string
	Tier      Tier
	Scopes    []string
	OrgID     int64
	CreatedBy int64
	Expires   *time.Time
	// Guard, if set, runs in the insert's transaction after the insert
	// (which holds SQLite's write lock); an error aborts the issue. The
	// console passes an org-exists check, so a key cannot outlive an org
	// deleted concurrently (see DeleteOrgWith / RevokeOrgKeysTx).
	Guard func(*sql.Tx) error
}

// IssueKeyWith creates a key with an optional org, creator and expiry. The
// raw key is returned exactly once and never stored or logged (T6).
func (s *Store) IssueKeyWith(o IssueOptions) (Key, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The prefix is the in-memory index; regenerate on the (2^-32) chance it
	// collides so an existing key is never shadowed.
	var raw string
	for {
		raw = newKeyString()
		if _, taken := s.keys[KeyPrefix(raw)]; !taken {
			break
		}
	}
	prefix := KeyPrefix(raw)
	hash := HashKey(raw, s.pepper)
	created := time.Now().UTC()
	var expires any
	if o.Expires != nil {
		expires = o.Expires.UTC().Format(time.RFC3339)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Key{}, "", err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO api_keys(prefix, hash, label, quota_tier, enabled, scopes, created, org_id, created_by, expires)
		VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
		prefix, hash[:], o.Label, tierName(o.Tier), strings.Join(o.Scopes, " "), created.Format(time.RFC3339), nullInt(o.OrgID), nullInt(o.CreatedBy), expires)
	if err != nil {
		return Key{}, "", err
	}
	id, _ := res.LastInsertId()
	if o.Guard != nil {
		if err := o.Guard(tx); err != nil {
			return Key{}, "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return Key{}, "", err
	}
	k := Key{ID: id, Prefix: prefix, Hash: hash, Label: o.Label, Tier: o.Tier, Enabled: true, Scopes: o.Scopes, Created: created,
		OrgID: o.OrgID, CreatedBy: o.CreatedBy, Expires: o.Expires}
	s.keys[prefix] = k
	return k, raw, nil
}

// OrgKeys lists an org's keys, newest first (hashes zeroed).
func (s *Store) OrgKeys(orgID int64) ([]Key, error) {
	rows, err := s.db.Query(`SELECT `+keyCols+` FROM api_keys WHERE org_id=? ORDER BY id DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		k.Hash = [32]byte{}
		out = append(out, k)
	}
	return out, rows.Err()
}

// OrgKey returns one of an org's keys; another org's key is ErrNotFound.
func (s *Store) OrgKey(orgID, id int64) (Key, error) {
	k, err := scanKey(s.db.QueryRow(`SELECT `+keyCols+` FROM api_keys WHERE id=? AND org_id=?`, id, orgID))
	if errors.Is(err, sql.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	k.Hash = [32]byte{}
	return k, err
}

// RevokeOrgKey revokes one of an org's keys.
func (s *Store) RevokeOrgKey(orgID, id int64) error {
	if _, err := s.OrgKey(orgID, id); err != nil {
		return err
	}
	return s.Revoke(id)
}

// RevokeOrgKeys revokes every key an org holds (org deletion).
func (s *Store) RevokeOrgKeys(orgID int64) error {
	keys, err := s.OrgKeys(orgID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.Revoked == nil {
			if err := s.Revoke(k.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// RevokeOrgKeysTx revokes every live key of an org inside tx (org
// deletion, with the org's delete in the same transaction). Call
// ForgetOrgKeys after the commit to update the in-memory index.
func (s *Store) RevokeOrgKeysTx(tx *sql.Tx, orgID int64) error {
	_, err := tx.Exec(`UPDATE api_keys SET enabled=0, revoked=? WHERE org_id=? AND revoked IS NULL`,
		time.Now().UTC().Format(time.RFC3339), orgID)
	return err
}

// ForgetOrgKeys marks every key of an org revoked in the in-memory index,
// so they stop authenticating at once (after RevokeOrgKeysTx committed).
func (s *Store) ForgetOrgKeys(orgID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := time.Now().UTC()
	for p, k := range s.keys {
		if k.OrgID == orgID && k.Revoked == nil {
			k.Enabled = false
			k.Revoked = &t
			s.keys[p] = k
		}
	}
}

// SetOrgTier moves every live key of an org to a new tier, in the table and
// the in-memory index, so a tier change takes effect at once.
func (s *Store) SetOrgTier(orgID int64, tier Tier) error {
	if _, err := s.db.Exec(`UPDATE api_keys SET quota_tier=? WHERE org_id=?`, tierName(tier), orgID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, k := range s.keys {
		if k.OrgID == orgID {
			k.Tier = tier
			s.keys[p] = k
		}
	}
	return nil
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
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
	return s.charge("key:"+strconv.FormatInt(keyID, 10), tier, rows)
}

// ChargePrincipal charges result rows to a principal's daily quota row.
func (s *Store) ChargePrincipal(p Principal, rows int64) (bool, error) {
	if p.Anonymous() {
		return true, nil
	}
	return s.charge(p.UsageKey, p.Tier, rows)
}

// UsageToday returns the rows charged to a usage key today.
func (s *Store) UsageToday(usageKey string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT rows FROM usage_principal WHERE principal=? AND day=?`, usageKey, time.Now().UTC().Format("2006-01-02")).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

func (s *Store) charge(principal string, tier Tier, rows int64) (bool, error) {
	if tier == TierAnonymous {
		// Anonymous has no key — charged separately via the IP limiter.
		return true, nil
	}
	if principal == "" {
		return false, errors.New("charge: empty principal")
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
	if err := tx.QueryRow(`SELECT rows FROM usage_principal WHERE principal=? AND day=?`, principal, day).Scan(&cur); err != nil {
		if err == sql.ErrNoRows {
			cur = 0
		} else {
			return false, err
		}
	}
	if cur+rows > quota {
		return false, ErrQuotaExceeded
	}
	if _, err := tx.Exec(`INSERT INTO usage_principal(principal, day, rows) VALUES (?,?,?)
		ON CONFLICT(principal, day) DO UPDATE SET rows=rows+excluded.rows`, principal, day, rows); err != nil {
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
	return s.LogPrincipalRequest(Principal{KeyID: keyID}, endpoint, status, latencyMS, resultCount, strategy)
}

// LogPrincipalRequest writes one request_log row for a principal. The
// principal column holds the usage key ("org:<id>", "key:<id>") — never an IP
// (T7) and never query text (T9).
func (s *Store) LogPrincipalRequest(p Principal, endpoint string, status int, latencyMS int64, resultCount int, strategy string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	var principal any
	if p.UsageKey != "" {
		principal = p.UsageKey
	}
	_, err := s.db.Exec(`INSERT INTO request_log(ts, key_id, endpoint, status, latency_ms, result_count, strategy, principal)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ts, p.KeyID, endpoint, status, latencyMS, resultCount, strategy, principal)
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
