package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"regexp"
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
	// AllowedTenants pins a multi-tenant Microsoft issuer (common,
	// organizations) to these Entra tenant IDs. Required for multi-tenant
	// org connections; optional for platform connections.
	AllowedTenants []string

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
	trust_email, allowed_orgs, saml_idp_metadata, saml_sp_key_enc, saml_sp_cert, saml_email_attr, saml_name_attr, saml_groups_attr, managed, created, allowed_tenants`

func (s *Store) scanConn(sc interface{ Scan(...any) error }) (Connection, error) {
	var c Connection
	var enabled, trust, managed int
	var secret, scopes, orgs, key, created, tenants string
	if err := sc.Scan(&c.ID, &c.OrgID, &c.Slug, &c.Kind, &c.Preset, &c.Name, &enabled, &c.Issuer, &c.ClientID, &secret, &scopes, &c.GroupsClaim,
		&trust, &orgs, &c.SAMLIdPMetadata, &key, &c.SAMLSPCert, &c.SAMLEmailAttr, &c.SAMLNameAttr, &c.SAMLGroupsAttr, &managed, &created, &tenants); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c, ErrNotFound
		}
		return c, err
	}
	c.Enabled, c.TrustEmail, c.Managed = enabled != 0, trust != 0, managed != 0
	c.Scopes = strings.Fields(scopes)
	c.AllowedOrgs = strings.Fields(orgs)
	c.AllowedTenants = strings.Fields(tenants)
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
	for i, t := range c.AllowedTenants {
		t = strings.ToLower(strings.TrimSpace(t))
		if !tenantRe.MatchString(t) {
			return ErrInvalid
		}
		c.AllowedTenants[i] = t
	}
	// A multi-tenant Entra issuer accepts every tenant's users; on an org
	// connection any tenant admin could assert the org's addresses, so it
	// must be pinned to the org's own tenants.
	if c.OrgID != 0 && c.Kind == KindOIDC && MultiTenantIssuer(c.Issuer) && len(c.AllowedTenants) == 0 {
		return ErrInvalid
	}
	return nil
}

var tenantRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

// MultiTenantIssuer reports whether issuer is a shared Microsoft endpoint
// (common, organizations, consumers) rather than one tenant.
func MultiTenantIssuer(issuer string) bool {
	if !strings.Contains(issuer, "login.microsoftonline.com") {
		return false
	}
	for _, t := range []string{"/common/", "/organizations/", "/consumers/"} {
		if strings.Contains(issuer+"/", t) {
			return true
		}
	}
	return false
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
	tenants := strings.Join(c.AllowedTenants, " ")
	if c.ID == 0 {
		res, err := s.db.ExecContext(ctx, `INSERT INTO connections(org_id, slug, kind, preset, name, enabled, issuer, client_id, client_secret_enc, scopes, groups_claim,
			trust_email, allowed_orgs, saml_idp_metadata, saml_sp_key_enc, saml_sp_cert, saml_email_attr, saml_name_attr, saml_groups_attr, managed, created, allowed_tenants)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			nullID(c.OrgID), c.Slug, c.Kind, c.Preset, c.Name, b2i(c.Enabled), c.Issuer, c.ClientID, secret, scopes, c.GroupsClaim,
			b2i(c.TrustEmail), orgs, c.SAMLIdPMetadata, key, c.SAMLSPCert, c.SAMLEmailAttr, c.SAMLNameAttr, c.SAMLGroupsAttr, b2i(c.Managed), now(), tenants)
		if err != nil {
			if isUnique(err) {
				return c, ErrConflict
			}
			return c, err
		}
		id, _ := res.LastInsertId()
		return s.ConnectionByID(ctx, id)
	}
	old, err := s.OrgConnection(ctx, c.OrgID, c.ID)
	if err != nil {
		return c, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE connections SET slug=?, preset=?, name=?, enabled=?, issuer=?, client_id=?,
		client_secret_enc=CASE WHEN ?='' THEN client_secret_enc ELSE ? END, scopes=?, groups_claim=?, trust_email=?, allowed_orgs=?,
		saml_idp_metadata=?, saml_sp_key_enc=CASE WHEN ?='' THEN saml_sp_key_enc ELSE ? END,
		saml_sp_cert=CASE WHEN ?='' THEN saml_sp_cert ELSE ? END, saml_email_attr=?, saml_name_attr=?, saml_groups_attr=?, managed=?, allowed_tenants=?
		WHERE id=? AND COALESCE(org_id,0)=? AND kind=?`,
		c.Slug, c.Preset, c.Name, b2i(c.Enabled), c.Issuer, c.ClientID, secret, secret, scopes, c.GroupsClaim, b2i(c.TrustEmail), orgs,
		c.SAMLIdPMetadata, key, key, c.SAMLSPCert, c.SAMLSPCert, c.SAMLEmailAttr, c.SAMLNameAttr, c.SAMLGroupsAttr, b2i(c.Managed), tenants,
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
	// Subjects are only meaningful to the IdP that issued them. If the
	// connection now points at a different IdP, its old identities and
	// sessions must not carry over, or the new IdP could replay a known
	// subject to become that user.
	if old.Issuer != c.Issuer || old.ClientID != c.ClientID || !sameSet(old.AllowedTenants, c.AllowedTenants) || (c.SAMLIdPMetadata != "" && old.SAMLIdPMetadata != c.SAMLIdPMetadata) {
		if _, err := tx.ExecContext(ctx, `DELETE FROM identities WHERE connection_id=?`, c.ID); err != nil {
			return c, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE connection_id=?`, c.ID); err != nil {
			return c, err
		}
	}
	if err := tx.Commit(); err != nil {
		return c, err
	}
	return s.ConnectionByID(ctx, c.ID)
}

// DeleteConnection deletes a connection within an org (0 = platform) and
// ends every session created through it, in one transaction. Sessions go
// first: sessions.connection_id is ON DELETE SET NULL, so once the
// connection is gone they can no longer be found. Identities, mappings and
// flows cascade.
func (s *Store) DeleteConnection(ctx context.Context, orgID, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM connections WHERE id=? AND COALESCE(org_id,0)=?`, id, orgID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE connection_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM connections WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
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
// to the org. A SCIM mapping recomputes SCIM members' roles at once (see
// DeleteGroupMapping).
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return m, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO group_mappings(org_id, source, connection_id, grp, role, created) VALUES (?,?,?,?,?,?)`,
		m.OrgID, m.Source, nullID(m.ConnectionID), m.Group, m.Role.String(), now())
	if err != nil {
		if isUnique(err) {
			return m, ErrConflict
		}
		return m, err
	}
	m.ID, _ = res.LastInsertId()
	if m.Source == SourceSCIM {
		if err := scimRecomputeOrgTx(ctx, tx, m.OrgID); err != nil {
			return m, err
		}
	}
	return m, tx.Commit()
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
//
// Removing (or adding) a SCIM mapping recomputes the role of every
// SCIM-sourced membership in the org at once, since SCIM keeps group
// membership here; if that would demote the last owner the change is
// refused with ErrLastOwner. SSO mappings take effect at each member's next
// sign-in, because the IdP's groups are only known then.
func (s *Store) DeleteGroupMapping(ctx context.Context, orgID, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var source string
	err = tx.QueryRowContext(ctx, `DELETE FROM group_mappings WHERE id=? AND org_id=? RETURNING source`, id, orgID).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if source == SourceSCIM {
		if err := scimRecomputeOrgTx(ctx, tx, orgID); err != nil {
			return err
		}
	}
	return tx.Commit()
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
