package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"time"
)

// Connection kinds.
const (
	KindOIDC   = "oidc"
	KindGitHub = "github"
	KindSAML   = "saml"
)

// Connection is an identity provider configuration. OrgID 0 means a platform
// connection, available to everyone on the login page.
type Connection struct {
	ID           int64
	OrgID        int64
	Slug         string
	Kind         string
	Preset       string
	Name         string
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string // opened; never rendered
	Scopes       []string
	GroupsClaim  string
	TrustEmail   bool
	AllowedOrgs  []string // GitHub org restriction

	SAMLIdPMetadata string
	SAMLSPKey       string // opened PEM; never rendered
	SAMLSPCert      string // PEM
	SAMLEmailAttr   string
	SAMLNameAttr    string
	SAMLGroupsAttr  string

	Managed bool // declared in AUGEO_AUTH_PROVIDERS_FILE; read-only in the console
	Created time.Time
}

// Platform reports whether the connection is a platform connection.
func (c Connection) Platform() bool { return c.OrgID == 0 }

const connCols = `id, COALESCE(org_id,0), slug, kind, preset, name, enabled, issuer, client_id, client_secret_enc, scopes, groups_claim,
	trust_email, allowed_orgs, saml_idp_metadata, saml_sp_key_enc, saml_sp_cert, saml_email_attr, saml_name_attr, saml_groups_attr, managed, created`

func (s *Store) scanConn(sc interface{ Scan(...any) error }) (Connection, error) {
	var c Connection
	var enabled, trust, managed int
	var secret, scopes, orgs, key, created string
	if err := sc.Scan(&c.ID, &c.OrgID, &c.Slug, &c.Kind, &c.Preset, &c.Name, &enabled, &c.Issuer, &c.ClientID, &secret, &scopes, &c.GroupsClaim,
		&trust, &orgs, &c.SAMLIdPMetadata, &key, &c.SAMLSPCert, &c.SAMLEmailAttr, &c.SAMLNameAttr, &c.SAMLGroupsAttr, &managed, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c, ErrNotFound
		}
		return c, err
	}
	c.Enabled, c.TrustEmail, c.Managed = enabled != 0, trust != 0, managed != 0
	c.Scopes = strings.Fields(scopes)
	c.AllowedOrgs = strings.Fields(orgs)
	c.Created = parseTS(created)
	var err error
	if c.ClientSecret, err = s.open(secret); err != nil {
		return c, err
	}
	if c.SAMLSPKey, err = s.open(key); err != nil {
		return c, err
	}
	return c, nil
}

// ConnectionByID returns any connection. Use OrgConnection from org-scoped
// handlers.
func (s *Store) ConnectionByID(ctx context.Context, id int64) (Connection, error) {
	return s.scanConn(s.db.QueryRowContext(ctx, `SELECT `+connCols+` FROM connections WHERE id=?`, id))
}

// ConnectionBySlug returns any connection by slug.
func (s *Store) ConnectionBySlug(ctx context.Context, slug string) (Connection, error) {
	return s.scanConn(s.db.QueryRowContext(ctx, `SELECT `+connCols+` FROM connections WHERE slug=?`, slug))
}

// OrgConnection returns a connection only if it belongs to orgID (0 =
// platform).
func (s *Store) OrgConnection(ctx context.Context, orgID, id int64) (Connection, error) {
	return s.scanConn(s.db.QueryRowContext(ctx, `SELECT `+connCols+` FROM connections WHERE id=? AND COALESCE(org_id,0)=?`, id, orgID))
}

// Connections lists connections for an org (0 = platform connections).
func (s *Store) Connections(ctx context.Context, orgID int64) ([]Connection, error) {
	return s.listConns(ctx, `SELECT `+connCols+` FROM connections WHERE COALESCE(org_id,0)=? ORDER BY name`, orgID)
}

// LoginConnections lists enabled platform connections for the login page.
func (s *Store) LoginConnections(ctx context.Context) ([]Connection, error) {
	return s.listConns(ctx, `SELECT `+connCols+` FROM connections WHERE org_id IS NULL AND enabled=1 ORDER BY name`)
}

// OrgLoginConnections lists an org's enabled connections.
func (s *Store) OrgLoginConnections(ctx context.Context, orgID int64) ([]Connection, error) {
	return s.listConns(ctx, `SELECT `+connCols+` FROM connections WHERE org_id=? AND enabled=1 ORDER BY name`, orgID)
}

func (s *Store) listConns(ctx context.Context, q string, args ...any) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		c, err := s.scanConn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func validateConn(c *Connection) error {
	c.Name = strings.TrimSpace(c.Name)
	c.Slug = strings.TrimSpace(c.Slug)
	if c.Name == "" || len(c.Name) > 100 || !ValidSlug(c.Slug) {
		return ErrInvalid
	}
	switch c.Kind {
	case KindOIDC:
		u, err := url.Parse(c.Issuer)
		if err != nil || u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) || u.Host == "" {
			return ErrInvalid
		}
		if c.ClientID == "" {
			return ErrInvalid
		}
	case KindGitHub:
		if c.ClientID == "" {
			return ErrInvalid
		}
	case KindSAML:
	default:
		return ErrInvalid
	}
	return nil
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// SaveConnection inserts (ID 0) or updates a connection. On update an empty
// ClientSecret or SAMLSPKey keeps the stored value, so a form that never
// echoes secrets can be resubmitted safely. On update the org must match.
func (s *Store) SaveConnection(ctx context.Context, c Connection) (Connection, error) {
	if err := validateConn(&c); err != nil {
		return c, err
	}
	secret, err := s.seal(c.ClientSecret)
	if err != nil {
		return c, err
	}
	key, err := s.seal(c.SAMLSPKey)
	if err != nil {
		return c, err
	}
	scopes := strings.Join(c.Scopes, " ")
	orgs := strings.Join(c.AllowedOrgs, " ")
	if c.ID == 0 {
		res, err := s.db.ExecContext(ctx, `INSERT INTO connections(org_id, slug, kind, preset, name, enabled, issuer, client_id, client_secret_enc, scopes, groups_claim,
			trust_email, allowed_orgs, saml_idp_metadata, saml_sp_key_enc, saml_sp_cert, saml_email_attr, saml_name_attr, saml_groups_attr, managed, created)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			nullID(c.OrgID), c.Slug, c.Kind, c.Preset, c.Name, b2i(c.Enabled), c.Issuer, c.ClientID, secret, scopes, c.GroupsClaim,
			b2i(c.TrustEmail), orgs, c.SAMLIdPMetadata, key, c.SAMLSPCert, c.SAMLEmailAttr, c.SAMLNameAttr, c.SAMLGroupsAttr, b2i(c.Managed), now())
		if err != nil {
			if isUnique(err) {
				return c, ErrConflict
			}
			return c, err
		}
		id, _ := res.LastInsertId()
		return s.ConnectionByID(ctx, id)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE connections SET slug=?, preset=?, name=?, enabled=?, issuer=?, client_id=?,
		client_secret_enc=CASE WHEN ?='' THEN client_secret_enc ELSE ? END, scopes=?, groups_claim=?, trust_email=?, allowed_orgs=?,
		saml_idp_metadata=?, saml_sp_key_enc=CASE WHEN ?='' THEN saml_sp_key_enc ELSE ? END,
		saml_sp_cert=CASE WHEN ?='' THEN saml_sp_cert ELSE ? END, saml_email_attr=?, saml_name_attr=?, saml_groups_attr=?, managed=?
		WHERE id=? AND COALESCE(org_id,0)=? AND kind=?`,
		c.Slug, c.Preset, c.Name, b2i(c.Enabled), c.Issuer, c.ClientID, secret, secret, scopes, c.GroupsClaim, b2i(c.TrustEmail), orgs,
		c.SAMLIdPMetadata, key, key, c.SAMLSPCert, c.SAMLSPCert, c.SAMLEmailAttr, c.SAMLNameAttr, c.SAMLGroupsAttr, b2i(c.Managed),
		c.ID, c.OrgID, c.Kind)
	if err != nil {
		if isUnique(err) {
			return c, ErrConflict
		}
		return c, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return c, ErrNotFound
	}
	return s.ConnectionByID(ctx, c.ID)
}

// DeleteConnection deletes a connection within an org (0 = platform). Its
// identities, mappings and flows cascade; sessions keep the user signed in
// until they expire, so callers that want an immediate cut-off also call
// DeleteConnectionSessions.
func (s *Store) DeleteConnection(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM connections WHERE id=? AND COALESCE(org_id,0)=?`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- domains ---

// Domain is an org's claim on an email domain.
type Domain struct {
	ID          int64
	OrgID       int64
	Domain      string
	VerifyToken string
	Verified    *time.Time
	Created     time.Time
}

// TXTName is the DNS name that must carry the verification record.
func (d Domain) TXTName() string { return "_augeo-verify." + d.Domain }

// TXTValue is the expected TXT record value.
func (d Domain) TXTValue() string { return "augeo-verify=" + d.VerifyToken }

// ValidDomain is a syntactic check for a registrable-looking domain name.
func ValidDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// AddDomain records an unverified domain claim.
func (s *Store) AddDomain(ctx context.Context, orgID int64, domain string) (Domain, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if !ValidDomain(domain) {
		return Domain{}, ErrInvalid
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO domains(org_id, domain, verify_token, created) VALUES (?,?,?,?)`, orgID, domain, RandomToken(24), now())
	if err != nil {
		if isUnique(err) {
			return Domain{}, ErrConflict
		}
		return Domain{}, err
	}
	id, _ := res.LastInsertId()
	return s.OrgDomain(ctx, orgID, id)
}

func scanDomain(sc interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	var v sql.NullString
	var c string
	if err := sc.Scan(&d.ID, &d.OrgID, &d.Domain, &d.VerifyToken, &v, &c); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return d, ErrNotFound
		}
		return d, err
	}
	d.Verified, d.Created = parseNullTS(v), parseTS(c)
	return d, nil
}

// OrgDomain returns a domain within an org.
func (s *Store) OrgDomain(ctx context.Context, orgID, id int64) (Domain, error) {
	return scanDomain(s.db.QueryRowContext(ctx, `SELECT id, org_id, domain, verify_token, verified, created FROM domains WHERE id=? AND org_id=?`, id, orgID))
}

// Domains lists an org's domains.
func (s *Store) Domains(ctx context.Context, orgID int64) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, domain, verify_token, verified, created FROM domains WHERE org_id=? ORDER BY domain`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkDomainVerified marks a domain verified. Fails with ErrConflict if
// another org already verified it.
func (s *Store) MarkDomainVerified(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE domains SET verified=? WHERE id=? AND org_id=? AND verified IS NULL`, now(), id, orgID)
	if err != nil {
		if isUnique(err) {
			return ErrConflict
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.OrgDomain(ctx, orgID, id); err != nil {
			return err
		}
	}
	return nil
}

// DeleteDomain removes a domain claim.
func (s *Store) DeleteDomain(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM domains WHERE id=? AND org_id=?`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// OrgForDomain returns the org that has verified the email domain.
func (s *Store) OrgForDomain(ctx context.Context, domain string) (Org, error) {
	return scanOrg(s.db.QueryRowContext(ctx, `SELECT `+prefixCols("o.", orgCols)+` FROM domains d JOIN orgs o ON o.id=d.org_id
		WHERE d.domain=? AND d.verified IS NOT NULL`, strings.ToLower(domain)))
}

func (s *Store) orgHasVerifiedDomain(ctx context.Context, orgID int64, domain string) bool {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE org_id=? AND domain=? AND verified IS NOT NULL`, orgID, strings.ToLower(domain)).Scan(&n)
	return n > 0
}

func prefixCols(p, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

// --- group mappings ---

// Group mapping sources.
const (
	SourceSSO  = "sso"
	SourceSCIM = "scim"
)

// GroupMapping maps an IdP group (SSO assertion or SCIM group) to an org
// role.
type GroupMapping struct {
	ID           int64
	OrgID        int64
	Source       string
	ConnectionID int64
	Group        string
	Role         Role
	Created      time.Time
}

// AddGroupMapping adds a mapping. For SSO mappings the connection must belong
// to the org.
func (s *Store) AddGroupMapping(ctx context.Context, m GroupMapping) (GroupMapping, error) {
	m.Group = strings.TrimSpace(m.Group)
	if m.Group == "" || len(m.Group) > 256 || m.Role < RoleViewer || m.Role > RoleOwner {
		return m, ErrInvalid
	}
	switch m.Source {
	case SourceSSO:
		if _, err := s.OrgConnection(ctx, m.OrgID, m.ConnectionID); err != nil {
			return m, err
		}
	case SourceSCIM:
		m.ConnectionID = 0
	default:
		return m, ErrInvalid
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO group_mappings(org_id, source, connection_id, grp, role, created) VALUES (?,?,?,?,?,?)`,
		m.OrgID, m.Source, nullID(m.ConnectionID), m.Group, m.Role.String(), now())
	if err != nil {
		return m, err
	}
	m.ID, _ = res.LastInsertId()
	return m, nil
}

// GroupMappings lists an org's mappings.
func (s *Store) GroupMappings(ctx context.Context, orgID int64) ([]GroupMapping, error) {
	return s.groupMappings(ctx, `SELECT id, org_id, source, COALESCE(connection_id,0), grp, role, created FROM group_mappings WHERE org_id=? ORDER BY source, grp`, orgID)
}

func (s *Store) groupMappings(ctx context.Context, q string, args ...any) ([]GroupMapping, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMapping
	for rows.Next() {
		var m GroupMapping
		var role, c string
		if err := rows.Scan(&m.ID, &m.OrgID, &m.Source, &m.ConnectionID, &m.Group, &role, &c); err != nil {
			return nil, err
		}
		m.Role, m.Created = ParseRole(role), parseTS(c)
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteGroupMapping removes a mapping within an org.
func (s *Store) DeleteGroupMapping(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM group_mappings WHERE id=? AND org_id=?`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MappedRole returns the highest role any of groups maps to for an SSO
// connection, and whether the connection has any mappings at all.
func (s *Store) MappedRole(ctx context.Context, orgID, connectionID int64, groups []string) (Role, bool, error) {
	ms, err := s.groupMappings(ctx, `SELECT id, org_id, source, COALESCE(connection_id,0), grp, role, created FROM group_mappings
		WHERE org_id=? AND source='sso' AND connection_id=?`, orgID, connectionID)
	if err != nil {
		return RoleNone, false, err
	}
	return highestRole(ms, groups), len(ms) > 0, nil
}

func highestRole(ms []GroupMapping, groups []string) Role {
	set := make(map[string]bool, len(groups))
	for _, g := range groups {
		set[g] = true
	}
	best := RoleNone
	for _, m := range ms {
		if set[m.Group] && m.Role > best {
			best = m.Role
		}
	}
	return best
}
