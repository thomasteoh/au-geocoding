package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// Session is a signed-in browser.
type Session struct {
	IDHash       []byte
	UserID       int64
	CSRF         string
	ConnectionID int64
	Method       string // oidc, github, saml, passkey
	IdPSID       string
	IdPSub       string
	IDToken      string // opened; for RP-initiated logout id_token_hint
	UserAgent    string
	Created      time.Time
	LastSeen     time.Time
	Expires      time.Time // absolute expiry
}

// SessionPolicy bounds session lifetime.
type SessionPolicy struct {
	Idle time.Duration
	Max  time.Duration
}

// NewSession is what a successful login hands to CreateSession.
type NewSession struct {
	UserID       int64
	ConnectionID int64
	Method       string
	IdPSID       string
	IdPSub       string
	IDToken      string
	UserAgent    string
}

// CreateSession stores a session and returns the raw ID for the cookie. The
// raw ID is never stored (auth.md A10).
func (s *Store) CreateSession(ctx context.Context, n NewSession, p SessionPolicy) (raw string, sess Session, err error) {
	raw = RandomToken(32)
	tok := ""
	if n.IDToken != "" && s.box != nil {
		if tok, err = s.seal(n.IDToken); err != nil {
			return "", sess, err
		}
	}
	ua := n.UserAgent
	if len(ua) > 200 {
		ua = ua[:200]
	}
	t := clock()
	sess = Session{IDHash: HashToken(raw), UserID: n.UserID, CSRF: RandomToken(32), ConnectionID: n.ConnectionID, Method: n.Method,
		IdPSID: n.IdPSID, IdPSub: n.IdPSub, IDToken: n.IDToken, UserAgent: ua, Created: t, LastSeen: t, Expires: t.Add(p.Max)}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, csrf, connection_id, method, idp_sid, idp_sub, id_token_enc, user_agent, created, last_seen, expires)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, sess.IDHash, n.UserID, sess.CSRF, nullID(n.ConnectionID), n.Method, n.IdPSID, n.IdPSub, tok, ua,
		ts(t), ts(t), ts(sess.Expires))
	if err != nil {
		return "", sess, err
	}
	s.touchLogin(ctx, n.UserID)
	return raw, sess, nil
}

const sessCols = `id_hash, user_id, csrf, COALESCE(connection_id,0), method, idp_sid, idp_sub, id_token_enc, user_agent, created, last_seen, expires`

func (s *Store) scanSession(sc interface{ Scan(...any) error }) (Session, error) {
	var x Session
	var tok, c, l, e string
	if err := sc.Scan(&x.IDHash, &x.UserID, &x.CSRF, &x.ConnectionID, &x.Method, &x.IdPSID, &x.IdPSub, &tok, &x.UserAgent, &c, &l, &e); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return x, ErrNotFound
		}
		return x, err
	}
	x.Created, x.LastSeen, x.Expires = parseTS(c), parseTS(l), parseTS(e)
	if tok != "" && s.box != nil {
		x.IDToken, _ = s.open(tok)
	}
	return x, nil
}

// LookupSession resolves a raw cookie value to a live session and its active
// user. Expired or idle sessions are deleted and reported as ErrNotFound.
// last_seen is written at most once a minute.
func (s *Store) LookupSession(ctx context.Context, raw string, p SessionPolicy) (Session, User, error) {
	if raw == "" || len(raw) > 128 {
		return Session{}, User{}, ErrNotFound
	}
	h := HashToken(raw)
	sess, err := s.scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessCols+` FROM sessions WHERE id_hash=?`, h))
	if err != nil {
		return sess, User{}, err
	}
	t := clock()
	if !t.Before(sess.Expires) || (p.Idle > 0 && t.Sub(sess.LastSeen) > p.Idle) {
		s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, h)
		return Session{}, User{}, ErrNotFound
	}
	u, err := s.UserByID(ctx, sess.UserID)
	if err != nil {
		return Session{}, User{}, err
	}
	if !u.Active() {
		s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID)
		return Session{}, User{}, ErrNotFound
	}
	if t.Sub(sess.LastSeen) > time.Minute {
		s.db.ExecContext(ctx, `UPDATE sessions SET last_seen=? WHERE id_hash=?`, ts(t), h)
		sess.LastSeen = t
	}
	return sess, u, nil
}

// CheckCSRF compares a submitted token with the session's in constant time.
func (sess Session) CheckCSRF(tok string) bool {
	return tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRF)) == 1
}

// DeleteSession ends one session by its hash.
func (s *Store) DeleteSession(ctx context.Context, idHash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, idHash)
	return err
}

// UserSessions lists a user's live sessions, newest first.
func (s *Store) UserSessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessCols+` FROM sessions WHERE user_id=? AND expires>? ORDER BY last_seen DESC`, userID, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		x, err := s.scanSession(rows)
		if err != nil {
			return nil, err
		}
		x.IDToken = ""
		out = append(out, x)
	}
	return out, rows.Err()
}

// DeleteUserSession ends one of the user's own sessions. The hash comes from
// a form, so the user ID is part of the match.
func (s *Store) DeleteUserSession(ctx context.Context, userID int64, idHash []byte) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND id_hash=?`, userID, idHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUserSessions ends every session for a user, optionally keeping one.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, keep []byte) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, userID, keep)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteIdPSessions ends sessions created through a connection for an IdP
// session ID or, when sid is empty, for an IdP subject (back-channel logout).
func (s *Store) DeleteIdPSessions(ctx context.Context, connectionID int64, sid, sub string) (int64, error) {
	var res sql.Result
	var err error
	switch {
	case sid != "":
		res, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE connection_id=? AND idp_sid=?`, connectionID, sid)
	case sub != "":
		res, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE connection_id=? AND idp_sub=?`, connectionID, sub)
	default:
		return 0, ErrInvalid
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteConnectionSessions ends every session created through a connection.
func (s *Store) DeleteConnectionSessions(ctx context.Context, connectionID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE connection_id=?`, connectionID)
	return err
}

// RecordLogoutJTI records a back-channel logout token ID. It returns false if
// the jti was already seen (replay, auth.md A6).
func (s *Store) RecordLogoutJTI(ctx context.Context, connectionID int64, jti string, exp time.Time) (bool, error) {
	s.db.ExecContext(ctx, `DELETE FROM logout_jtis WHERE expires<?`, now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO logout_jtis(connection_id, jti, expires) VALUES (?,?,?)`, connectionID, jti, ts(exp))
	if isUnique(err) {
		return false, nil
	}
	return err == nil, err
}

// --- login flows ---

// Flow is an in-flight interactive login (or passkey ceremony) bound to the
// browser that started it (auth.md A1).
type Flow struct {
	Kind         string // oidc, github, saml, passkey-login, passkey-register
	ConnectionID int64
	Nonce        string
	PKCEVerifier string
	RequestID    string
	ReturnTo     string
	Data         string // protocol-specific JSON (e.g. WebAuthn session data)
	UserID       int64
}

// FlowTTL bounds how long a user has to complete a login at the IdP.
const FlowTTL = 10 * time.Minute

// StartFlow stores a flow and returns the state (sent to the IdP) and the
// binding (set as the flow cookie).
func (s *Store) StartFlow(ctx context.Context, f Flow) (state, binding string, err error) {
	state, binding = RandomToken(32), RandomToken(32)
	s.db.ExecContext(ctx, `DELETE FROM auth_flows WHERE expires<?`, now())
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_flows(state_hash, binding, kind, connection_id, nonce, pkce_verifier, request_id, return_to, data, user_id, expires)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, HashToken(state), binding, f.Kind, nullID(f.ConnectionID), f.Nonce, f.PKCEVerifier, f.RequestID, f.ReturnTo,
		f.Data, nullID(f.UserID), ts(clock().Add(FlowTTL)))
	return state, binding, err
}

// TakeFlow consumes a flow by state. The binding from the browser's flow
// cookie must match; the row is deleted whether or not it does, so a state
// can be tried once.
func (s *Store) TakeFlow(ctx context.Context, state, binding string) (Flow, error) {
	if state == "" {
		return Flow{}, ErrNotFound
	}
	// The row is consumed even with no binding, so a state lured into a
	// cookie-less browser cannot be retried elsewhere.
	h := HashToken(state)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Flow{}, err
	}
	defer tx.Rollback()
	var f Flow
	var b, exp string
	err = tx.QueryRowContext(ctx, `SELECT binding, kind, COALESCE(connection_id,0), nonce, pkce_verifier, request_id, return_to, data, COALESCE(user_id,0), expires
		FROM auth_flows WHERE state_hash=?`, h).Scan(&b, &f.Kind, &f.ConnectionID, &f.Nonce, &f.PKCEVerifier, &f.RequestID, &f.ReturnTo, &f.Data, &f.UserID, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return Flow{}, ErrNotFound
	}
	if err != nil {
		return Flow{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_flows WHERE state_hash=?`, h); err != nil {
		return Flow{}, err
	}
	if err := tx.Commit(); err != nil {
		return Flow{}, err
	}
	if subtle.ConstantTimeCompare([]byte(b), []byte(binding)) != 1 || !clock().Before(parseTS(exp)) {
		return Flow{}, ErrNotFound
	}
	return f, nil
}
