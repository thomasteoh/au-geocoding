package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"time"
)

// --- JWT issuers (API bearer tokens) ---

// JWTIssuer is an org's registration of an OAuth2/OIDC issuer whose access
// tokens the public API accepts (auth.md "API: bearer tokens").
type JWTIssuer struct {
	ID              int64
	OrgID           int64
	Issuer          string
	Audience        string
	JWKSURL         string
	ScopePrefix     string
	AllowedSubjects []string
	Enabled         bool
	Created         time.Time
}

const issuerCols = `id, org_id, issuer, audience, jwks_url, scope_prefix, allowed_subjects, enabled, created`

func scanIssuer(sc interface{ Scan(...any) error }) (JWTIssuer, error) {
	var j JWTIssuer
	var subs, c string
	var en int
	if err := sc.Scan(&j.ID, &j.OrgID, &j.Issuer, &j.Audience, &j.JWKSURL, &j.ScopePrefix, &subs, &en, &c); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return j, ErrNotFound
		}
		return j, err
	}
	j.AllowedSubjects = strings.Fields(subs)
	j.Enabled = en != 0
	j.Created = parseTS(c)
	return j, nil
}

func validHTTPSURL(s string, allowEmpty bool) bool {
	if s == "" {
		return allowEmpty
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http" && isLoopback(u.Hostname())
}

// SaveJWTIssuer inserts (ID 0) or updates an org's issuer.
func (s *Store) SaveJWTIssuer(ctx context.Context, j JWTIssuer) (JWTIssuer, error) {
	j.Issuer = strings.TrimSpace(j.Issuer)
	j.Audience = strings.TrimSpace(j.Audience)
	j.JWKSURL = strings.TrimSpace(j.JWKSURL)
	if !validHTTPSURL(j.Issuer, false) || j.Audience == "" || len(j.Audience) > 512 || !validHTTPSURL(j.JWKSURL, true) || len(j.ScopePrefix) > 64 {
		return j, ErrInvalid
	}
	subs := strings.Join(j.AllowedSubjects, " ")
	if j.ID == 0 {
		id, err := s.insertJWTIssuer(ctx, j, subs)
		if err != nil {
			if isUnique(err) {
				return j, ErrConflict
			}
			return j, err
		}
		j.ID = id
		return s.OrgJWTIssuer(ctx, j.OrgID, j.ID)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE jwt_issuers SET issuer=?, audience=?, jwks_url=?, scope_prefix=?, allowed_subjects=?, enabled=? WHERE id=? AND org_id=?`,
		j.Issuer, j.Audience, j.JWKSURL, j.ScopePrefix, subs, b2i(j.Enabled), j.ID, j.OrgID)
	if err != nil {
		if isUnique(err) {
			return j, ErrConflict
		}
		return j, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return j, ErrNotFound
	}
	return s.OrgJWTIssuer(ctx, j.OrgID, j.ID)
}

// OrgJWTIssuer returns an issuer within an org.
func (s *Store) OrgJWTIssuer(ctx context.Context, orgID, id int64) (JWTIssuer, error) {
	return scanIssuer(s.db.QueryRowContext(ctx, `SELECT `+issuerCols+` FROM jwt_issuers WHERE id=? AND org_id=?`, id, orgID))
}

// JWTIssuers lists an org's issuers.
func (s *Store) JWTIssuers(ctx context.Context, orgID int64) ([]JWTIssuer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+issuerCols+` FROM jwt_issuers WHERE org_id=? ORDER BY issuer`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JWTIssuer
	for rows.Next() {
		j, err := scanIssuer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// EnabledJWTIssuers returns the enabled registrations for iss (one per
// audience).
func (s *Store) EnabledJWTIssuers(ctx context.Context, iss string) ([]JWTIssuer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+issuerCols+` FROM jwt_issuers WHERE issuer=? AND enabled=1 ORDER BY id`, iss)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JWTIssuer
	for rows.Next() {
		j, err := scanIssuer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// DeleteJWTIssuer removes an issuer within an org.
func (s *Store) DeleteJWTIssuer(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM jwt_issuers WHERE id=? AND org_id=?`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- SCIM tokens ---

// SCIMToken is an org's SCIM bearer token (metadata only).
type SCIMToken struct {
	ID       int64
	OrgID    int64
	Prefix   string
	Label    string
	Created  time.Time
	LastUsed *time.Time
	Revoked  *time.Time
}

// scimTokenPrefix marks SCIM tokens so a leaked one is recognisable.
const scimTokenPrefix = "augscim_"

// CreateSCIMToken issues a token; the raw value is returned once.
func (s *Store) CreateSCIMToken(ctx context.Context, orgID int64, label string) (SCIMToken, string, error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 100 {
		return SCIMToken{}, "", ErrInvalid
	}
	raw := scimTokenPrefix + RandomToken(32)
	res, err := s.db.ExecContext(ctx, `INSERT INTO scim_tokens(org_id, prefix, hash, label, created) VALUES (?,?,?,?,?)`,
		orgID, raw[:len(scimTokenPrefix)+6], HashToken(raw), label, now())
	if err != nil {
		return SCIMToken{}, "", err
	}
	id, _ := res.LastInsertId()
	toks, err := s.SCIMTokens(ctx, orgID)
	if err != nil {
		return SCIMToken{}, "", err
	}
	for _, t := range toks {
		if t.ID == id {
			return t, raw, nil
		}
	}
	return SCIMToken{}, "", ErrNotFound
}

// SCIMTokens lists an org's tokens.
func (s *Store) SCIMTokens(ctx context.Context, orgID int64) ([]SCIMToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, prefix, label, created, last_used, revoked FROM scim_tokens WHERE org_id=? ORDER BY id DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SCIMToken
	for rows.Next() {
		var t SCIMToken
		var c string
		var lu, rv sql.NullString
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Prefix, &t.Label, &c, &lu, &rv); err != nil {
			return nil, err
		}
		t.Created, t.LastUsed, t.Revoked = parseTS(c), parseNullTS(lu), parseNullTS(rv)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeSCIMToken revokes a token within an org.
func (s *Store) RevokeSCIMToken(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE scim_tokens SET revoked=? WHERE id=? AND org_id=? AND revoked IS NULL`, now(), id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateSCIM resolves a raw SCIM token to its org. Any failure is
// ErrNotFound.
func (s *Store) AuthenticateSCIM(ctx context.Context, raw string) (int64, error) {
	if !strings.HasPrefix(raw, scimTokenPrefix) || len(raw) > 128 {
		return 0, ErrNotFound
	}
	h := HashToken(raw)
	var id, org int64
	var stored []byte
	var rv sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, org_id, hash, revoked FROM scim_tokens WHERE hash=?`, h).Scan(&id, &org, &stored, &rv)
	if err != nil || rv.Valid || subtle.ConstantTimeCompare(stored, h) != 1 {
		return 0, ErrNotFound
	}
	s.db.ExecContext(ctx, `UPDATE scim_tokens SET last_used=? WHERE id=?`, now(), id)
	return org, nil
}

// --- passkeys ---

// Passkey is a stored WebAuthn credential. Data is the JSON-encoded
// webauthn.Credential, owned by the passkey package.
type Passkey struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	Data         string
	Name         string
	Created      time.Time
	LastUsed     *time.Time
}

// WebAuthnHandle returns the user's stable WebAuthn user handle, creating a
// random one on first use (never the database ID, which would leak counts).
func (s *Store) WebAuthnHandle(ctx context.Context, userID int64) ([]byte, error) {
	var h []byte
	err := s.db.QueryRowContext(ctx, `SELECT handle FROM webauthn_handles WHERE user_id=?`, userID).Scan(&h)
	if err == nil {
		return h, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	h = []byte(RandomToken(32))
	if _, err := s.db.ExecContext(ctx, `INSERT INTO webauthn_handles(user_id, handle) VALUES (?,?)`, userID, h); err != nil {
		return nil, err
	}
	return h, nil
}

// UserByWebAuthnHandle resolves a user handle from a discoverable login.
func (s *Store) UserByWebAuthnHandle(ctx context.Context, handle []byte) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+prefixCols("u.", userCols)+` FROM webauthn_handles h JOIN users u ON u.id=h.user_id WHERE h.handle=?`, handle))
}

// Passkeys lists a user's credentials.
func (s *Store) Passkeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, credential, data, name, created, last_used FROM passkeys WHERE user_id=? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		var c string
		var lu sql.NullString
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.Data, &p.Name, &c, &lu); err != nil {
			return nil, err
		}
		p.Created, p.LastUsed = parseTS(c), parseNullTS(lu)
		out = append(out, p)
	}
	return out, rows.Err()
}

// AddPasskey stores a new credential.
func (s *Store) AddPasskey(ctx context.Context, p Passkey) (int64, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 100 {
		name = name[:100]
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO passkeys(user_id, credential, data, name, created) VALUES (?,?,?,?,?)`, p.UserID, p.CredentialID, p.Data, name, now())
	if err != nil {
		if isUnique(err) {
			return 0, ErrConflict
		}
		return 0, err
	}
	return res.LastInsertId()
}

// UpdatePasskeyData saves the credential after a login (sign count, flags).
func (s *Store) UpdatePasskeyData(ctx context.Context, userID int64, credID []byte, data string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET data=?, last_used=? WHERE user_id=? AND credential=?`, data, now(), userID, credID)
	return err
}

// DeletePasskey removes one of the user's credentials.
func (s *Store) DeletePasskey(ctx context.Context, userID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id=? AND user_id=?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- audit ---

// AuditEvent is one audit log row. It never holds secrets, raw tokens or
// geocoding queries.
type AuditEvent struct {
	ID      int64
	TS      time.Time
	OrgID   int64
	ActorID int64
	Actor   string // email, "scim", "system", "idp"
	Action  string
	Target  string
	Detail  string
}

// Audit appends an event. Failures are returned but callers usually only log
// them: an audit write must never be the reason a user action half-applies.
func (s *Store) Audit(ctx context.Context, e AuditEvent) error {
	if len(e.Detail) > 1000 {
		e.Detail = e.Detail[:1000]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(ts, org_id, actor_id, actor, action, target, detail) VALUES (?,?,?,?,?,?,?)`,
		now(), nullID(e.OrgID), nullID(e.ActorID), e.Actor, e.Action, e.Target, e.Detail)
	return err
}

// AuditLog lists an org's events newest first (orgID 0 = platform events),
// before an optional ID for paging.
func (s *Store) AuditLog(ctx context.Context, orgID int64, before int64, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if before <= 0 {
		before = 1<<62 - 1
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, COALESCE(org_id,0), COALESCE(actor_id,0), actor, action, target, detail FROM audit_events
		WHERE COALESCE(org_id,0)=? AND id<? ORDER BY id DESC LIMIT ?`, orgID, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var t string
		if err := rows.Scan(&e.ID, &t, &e.OrgID, &e.ActorID, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = parseTS(t)
		out = append(out, e)
	}
	return out, rows.Err()
}
