package identity

import (
	"database/sql"
	"fmt"
)

// migrations are applied in order and recorded in identity_migrations. Never
// edit an applied migration; append a new one.
var migrations = []string{
	// 1: core identity model.
	`
CREATE TABLE users (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
	name           TEXT NOT NULL DEFAULT '',
	status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deprovisioned')),
	platform_admin INTEGER NOT NULL DEFAULT 0,
	created        TEXT NOT NULL,
	last_login     TEXT
);
CREATE TABLE orgs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	slug          TEXT NOT NULL UNIQUE COLLATE NOCASE,
	name          TEXT NOT NULL,
	tier          TEXT NOT NULL DEFAULT 'demo',
	sso_enforced  INTEGER NOT NULL DEFAULT 0,
	jit_enabled   INTEGER NOT NULL DEFAULT 0,
	default_role  TEXT NOT NULL DEFAULT 'viewer' CHECK (default_role IN ('viewer','developer','admin')),
	personal      INTEGER NOT NULL DEFAULT 0,
	created       TEXT NOT NULL
);
CREATE TABLE memberships (
	org_id  INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role    TEXT NOT NULL CHECK (role IN ('viewer','developer','admin','owner')),
	source  TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','jit','scim','group','invite','signup')),
	created TEXT NOT NULL,
	PRIMARY KEY (org_id, user_id)
);
CREATE INDEX idx_memberships_user ON memberships(user_id);
CREATE TABLE connections (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id             INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
	slug               TEXT NOT NULL UNIQUE,
	kind               TEXT NOT NULL CHECK (kind IN ('oidc','github','saml')),
	preset             TEXT NOT NULL DEFAULT 'generic',
	name               TEXT NOT NULL,
	enabled            INTEGER NOT NULL DEFAULT 1,
	issuer             TEXT NOT NULL DEFAULT '',
	client_id          TEXT NOT NULL DEFAULT '',
	client_secret_enc  TEXT NOT NULL DEFAULT '',
	scopes             TEXT NOT NULL DEFAULT '',
	groups_claim       TEXT NOT NULL DEFAULT '',
	trust_email        INTEGER NOT NULL DEFAULT 0,
	allowed_orgs       TEXT NOT NULL DEFAULT '',
	saml_idp_metadata  TEXT NOT NULL DEFAULT '',
	saml_sp_key_enc    TEXT NOT NULL DEFAULT '',
	saml_sp_cert       TEXT NOT NULL DEFAULT '',
	saml_email_attr    TEXT NOT NULL DEFAULT '',
	saml_name_attr     TEXT NOT NULL DEFAULT '',
	saml_groups_attr   TEXT NOT NULL DEFAULT '',
	managed            INTEGER NOT NULL DEFAULT 0,
	created            TEXT NOT NULL
);
CREATE TABLE identities (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
	subject       TEXT NOT NULL,
	email         TEXT NOT NULL DEFAULT '',
	created       TEXT NOT NULL,
	last_login    TEXT,
	UNIQUE (connection_id, subject)
);
CREATE INDEX idx_identities_user ON identities(user_id);
CREATE TABLE domains (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id       INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	domain       TEXT NOT NULL COLLATE NOCASE,
	verify_token TEXT NOT NULL,
	verified     TEXT,
	created      TEXT NOT NULL,
	UNIQUE (org_id, domain)
);
-- A domain can be verified by one org only.
CREATE UNIQUE INDEX idx_domains_verified ON domains(domain) WHERE verified IS NOT NULL;
CREATE TABLE group_mappings (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id        INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	source        TEXT NOT NULL CHECK (source IN ('sso','scim')),
	connection_id INTEGER REFERENCES connections(id) ON DELETE CASCADE,
	grp           TEXT NOT NULL,
	role          TEXT NOT NULL CHECK (role IN ('viewer','developer','admin','owner')),
	created       TEXT NOT NULL
);
CREATE INDEX idx_group_mappings_org ON group_mappings(org_id);
CREATE UNIQUE INDEX idx_group_mappings_unique ON group_mappings(org_id, source, COALESCE(connection_id, 0), grp);
CREATE TABLE invites (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	email      TEXT NOT NULL COLLATE NOCASE,
	role       TEXT NOT NULL CHECK (role IN ('viewer','developer','admin','owner')),
	invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
	created    TEXT NOT NULL,
	expires    TEXT NOT NULL,
	UNIQUE (org_id, email)
);
CREATE TABLE sessions (
	id_hash       BLOB PRIMARY KEY,
	user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf          TEXT NOT NULL,
	connection_id INTEGER REFERENCES connections(id) ON DELETE SET NULL,
	method        TEXT NOT NULL,
	idp_sid       TEXT NOT NULL DEFAULT '',
	idp_sub       TEXT NOT NULL DEFAULT '',
	id_token_enc  TEXT NOT NULL DEFAULT '',
	user_agent    TEXT NOT NULL DEFAULT '',
	created       TEXT NOT NULL,
	last_seen     TEXT NOT NULL,
	expires       TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_idp ON sessions(connection_id, idp_sid);
CREATE TABLE auth_flows (
	state_hash    BLOB PRIMARY KEY,
	binding       TEXT NOT NULL,
	kind          TEXT NOT NULL,
	connection_id INTEGER REFERENCES connections(id) ON DELETE CASCADE,
	nonce         TEXT NOT NULL DEFAULT '',
	pkce_verifier TEXT NOT NULL DEFAULT '',
	request_id    TEXT NOT NULL DEFAULT '',
	return_to     TEXT NOT NULL DEFAULT '',
	data          TEXT NOT NULL DEFAULT '',
	user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
	expires       TEXT NOT NULL
);
CREATE TABLE logout_jtis (
	connection_id INTEGER NOT NULL,
	jti           TEXT NOT NULL,
	expires       TEXT NOT NULL,
	PRIMARY KEY (connection_id, jti)
);
CREATE TABLE passkeys (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	credential   BLOB NOT NULL UNIQUE,
	data         TEXT NOT NULL,
	name         TEXT NOT NULL DEFAULT '',
	created      TEXT NOT NULL,
	last_used    TEXT
);
CREATE INDEX idx_passkeys_user ON passkeys(user_id);
CREATE TABLE webauthn_handles (
	user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
	handle  BLOB NOT NULL UNIQUE
);
CREATE TABLE scim_tokens (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id    INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	prefix    TEXT NOT NULL,
	hash      BLOB NOT NULL UNIQUE,
	label     TEXT NOT NULL,
	created   TEXT NOT NULL,
	last_used TEXT,
	revoked   TEXT
);
CREATE TABLE scim_users (
	org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	scim_id     TEXT NOT NULL UNIQUE,
	external_id TEXT NOT NULL DEFAULT '',
	active      INTEGER NOT NULL DEFAULT 1,
	data        TEXT NOT NULL DEFAULT '{}',
	created     TEXT NOT NULL,
	updated     TEXT NOT NULL,
	PRIMARY KEY (org_id, user_id)
);
CREATE TABLE scim_groups (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id       INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	scim_id      TEXT NOT NULL UNIQUE,
	external_id  TEXT NOT NULL DEFAULT '',
	display_name TEXT NOT NULL,
	created      TEXT NOT NULL,
	updated      TEXT NOT NULL,
	UNIQUE (org_id, display_name)
);
CREATE TABLE scim_group_members (
	group_id INTEGER NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
	user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	PRIMARY KEY (group_id, user_id)
);
CREATE TABLE jwt_issuers (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id           INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	issuer           TEXT NOT NULL,
	audience         TEXT NOT NULL,
	jwks_url         TEXT NOT NULL DEFAULT '',
	scope_prefix     TEXT NOT NULL DEFAULT '',
	allowed_subjects TEXT NOT NULL DEFAULT '',
	enabled          INTEGER NOT NULL DEFAULT 1,
	created          TEXT NOT NULL,
	-- Shared issuers (one Entra tenant, one Auth0 tenant) are told apart by
	-- audience, so no org can squat an issuer another org needs.
	UNIQUE (issuer, audience)
);
CREATE INDEX idx_jwt_issuers_iss ON jwt_issuers(issuer);
CREATE TABLE audit_events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	ts       TEXT NOT NULL,
	org_id   INTEGER,
	actor_id INTEGER,
	actor    TEXT NOT NULL,
	action   TEXT NOT NULL,
	target   TEXT NOT NULL DEFAULT '',
	detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_org_ts ON audit_events(org_id, ts);
`,
	// 2: Entra tenant allowlist on connections.
	`ALTER TABLE connections ADD COLUMN allowed_tenants TEXT NOT NULL DEFAULT '';`,
	// 3: connections a session has signed in through (per-org SSO proofs).
	`CREATE TABLE session_proofs (
	id_hash       BLOB NOT NULL REFERENCES sessions(id_hash) ON DELETE CASCADE,
	connection_id INTEGER NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
	created       TEXT NOT NULL,
	PRIMARY KEY (id_hash, connection_id)
);
CREATE INDEX idx_session_proofs_conn ON session_proofs(connection_id);`,
	// 4: SAML NameID format and qualifiers (JSON) for LogoutRequest, and
	// lookup of SAML logout flows by request ID.
	`ALTER TABLE sessions ADD COLUMN idp_sub_qual TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_auth_flows_request ON auth_flows(request_id);`,
	// 5: outbound mail queue (invite emails). recipient and body are blanked
	// once a message is sent or has finally failed; the row stays a while
	// (with the recipient hash) for rate limiting.
	`
CREATE TABLE mail_outbox (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id         INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
	kind           TEXT NOT NULL,
	recipient      TEXT NOT NULL,
	recipient_hash BLOB NOT NULL,
	subject        TEXT NOT NULL,
	body           TEXT NOT NULL,
	status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
	attempts       INTEGER NOT NULL DEFAULT 0,
	next_attempt   TEXT NOT NULL,
	last_error     TEXT NOT NULL DEFAULT '',
	created        TEXT NOT NULL,
	updated        TEXT NOT NULL
);
CREATE INDEX idx_mail_outbox_due ON mail_outbox(status, next_attempt);
CREATE INDEX idx_mail_outbox_org ON mail_outbox(org_id, created);
CREATE INDEX idx_mail_outbox_rcpt ON mail_outbox(recipient_hash, created);
-- StartFlow prunes expired flows on every call.
CREATE INDEX idx_auth_flows_expires ON auth_flows(expires);
`,
	// 6: reserved by a parallel branch. This no-op only keeps the numbering;
	// replace it with that branch's migration 6 when merging.
	`SELECT 1;`,
	// 7: tenant abuse limits. orgs.created_by counts the orgs a user created
	// (AUGEO_AUTH_MAX_ORGS_PER_USER); mail_outbox.sender_id bounds invite
	// emails per inviting user; JWT issuer registrations are unique per org,
	// not globally, so no org can squat an (issuer, audience) another org
	// needs (a pair registered by two orgs is refused as ambiguous).
	`
ALTER TABLE orgs ADD COLUMN created_by INTEGER REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX idx_orgs_created_by ON orgs(created_by);
ALTER TABLE mail_outbox ADD COLUMN sender_id INTEGER;
CREATE INDEX idx_mail_outbox_sender ON mail_outbox(sender_id, created);
CREATE TABLE jwt_issuers_v7 (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	org_id           INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
	issuer           TEXT NOT NULL,
	audience         TEXT NOT NULL,
	jwks_url         TEXT NOT NULL DEFAULT '',
	scope_prefix     TEXT NOT NULL DEFAULT '',
	allowed_subjects TEXT NOT NULL DEFAULT '',
	enabled          INTEGER NOT NULL DEFAULT 1,
	created          TEXT NOT NULL,
	UNIQUE (org_id, issuer, audience)
);
INSERT INTO jwt_issuers_v7(id, org_id, issuer, audience, jwks_url, scope_prefix, allowed_subjects, enabled, created)
	SELECT id, org_id, issuer, audience, jwks_url, scope_prefix, allowed_subjects, enabled, created FROM jwt_issuers;
DROP TABLE jwt_issuers;
ALTER TABLE jwt_issuers_v7 RENAME TO jwt_issuers;
CREATE INDEX idx_jwt_issuers_iss ON jwt_issuers(issuer, audience);
`,
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS identity_migrations (version INTEGER PRIMARY KEY, applied TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("identity migrate: %w", err)
	}
	var have int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM identity_migrations`).Scan(&have); err != nil {
		return fmt.Errorf("identity migrate: %w", err)
	}
	for i := have; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("identity migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_migrations(version, applied) VALUES (?, ?)`, i+1, now()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
