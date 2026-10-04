package console

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"augeocoding/internal/identity"
	"augeocoding/internal/oidcrp"
	"augeocoding/internal/samlsp"
)

// registerOrgIdentityRoutes mounts SSO connections, group mappings, SCIM
// tokens and OAuth (JWT) issuer pages. All are admin+; owner-only actions
// (mapping a group to owner) are checked in the handler.
func (s *Server) registerOrgIdentityRoutes(mux *http.ServeMux) {
	a := identity.RoleAdmin
	// Whoever controls an org's IdP or SCIM feed decides who its members are
	// and what roles they get, so those are owner-only. OAuth issuers only
	// admit API callers, which admins already manage through keys.
	o := identity.RoleOwner
	org := func(h func(http.ResponseWriter, *http.Request, connScope)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { h(w, r, orgScope(r)) }
	}
	mux.Handle("GET /console/orgs/{org}/sso", s.orgRoute(o, org(s.handleConnList)))
	mux.Handle("GET /console/orgs/{org}/sso/new", s.orgRoute(o, org(s.handleConnNew)))
	mux.Handle("POST /console/orgs/{org}/sso", s.orgPost(o, org(s.handleConnCreate)))
	mux.Handle("GET /console/orgs/{org}/sso/{id}", s.orgRoute(o, org(s.handleConnEdit)))
	mux.Handle("POST /console/orgs/{org}/sso/{id}", s.orgPost(o, org(s.handleConnUpdate)))
	mux.Handle("POST /console/orgs/{org}/sso/{id}/delete", s.orgPost(o, org(s.handleConnDelete)))
	mux.Handle("POST /console/orgs/{org}/sso/{id}/mappings", s.orgPost(o, s.handleSSOMappingAdd))
	mux.Handle("POST /console/orgs/{org}/sso/{id}/mappings/{mid}/delete", s.orgPost(o, s.handleSSOMappingDelete))

	mux.Handle("GET /console/orgs/{org}/scim", s.orgRoute(o, s.handleSCIM))
	mux.Handle("POST /console/orgs/{org}/scim/tokens", s.orgPost(o, s.handleSCIMTokenCreate))
	mux.Handle("POST /console/orgs/{org}/scim/tokens/{id}/revoke", s.orgPost(o, s.handleSCIMTokenRevoke))
	mux.Handle("POST /console/orgs/{org}/scim/mappings", s.orgPost(o, s.handleSCIMMappingAdd))
	mux.Handle("POST /console/orgs/{org}/scim/mappings/{mid}/delete", s.orgPost(o, s.handleSCIMMappingDelete))

	mux.Handle("GET /console/orgs/{org}/tokens", s.orgRoute(a, s.handleIssuers))
	mux.Handle("POST /console/orgs/{org}/tokens", s.orgPost(a, s.handleIssuerCreate))
	mux.Handle("GET /console/orgs/{org}/tokens/{id}", s.orgRoute(a, s.handleIssuerEdit))
	mux.Handle("POST /console/orgs/{org}/tokens/{id}", s.orgPost(a, s.handleIssuerUpdate))
	mux.Handle("POST /console/orgs/{org}/tokens/{id}/delete", s.orgPost(a, s.handleIssuerDelete))
}

// pathInt parses a numeric path value; 0 means invalid.
func pathInt(r *http.Request, name string) int64 {
	id, _ := pathID(r, name)
	return id
}

// --- SSO connections (shared by org and platform pages) ---

// connScope says whose connections a page manages: an org's (from the
// request context, never a form) or the platform's (OrgID 0).
type connScope struct {
	OrgID    int64
	OrgSlug  string
	Base     string // list page URL
	Platform bool
	Active   string
}

func orgScope(r *http.Request) connScope {
	oc := orgFrom(r.Context())
	return connScope{OrgID: oc.Org.ID, OrgSlug: oc.Org.Slug, Base: "/console/orgs/" + oc.Org.Slug + "/sso", Active: "sso"}
}

func platformScope(*http.Request) connScope {
	return connScope{Base: "/console/admin/connections", Platform: true, Active: "admin"}
}

// connView is what templates see of a connection. It deliberately has no
// client secret or SAML private key field (A11).
type connView struct {
	ID          int64
	Slug        string
	Kind        string
	Preset      string
	Name        string
	Enabled     bool
	Issuer      string
	ClientID    string
	HasSecret   bool
	ExtraScopes string
	GroupsClaim string
	TrustEmail  bool
	AllowedOrgs string

	SAMLIdPMetadata string
	SAMLSPCert      string // public certificate for the IdP admin
	SAMLEmailAttr   string
	SAMLNameAttr    string
	SAMLGroupsAttr  string

	Managed bool
	Created time.Time

	// Values the IdP admin needs.
	RedirectURI    string
	BackchannelURL string
	TestURL        string
	EntityID       string
	ACSURL         string
	MetadataURL    string
}

func (s *Server) viewConn(c identity.Connection) connView {
	v := connView{ID: c.ID, Slug: c.Slug, Kind: c.Kind, Preset: c.Preset, Name: c.Name, Enabled: c.Enabled, Issuer: c.Issuer,
		ClientID: c.ClientID, HasSecret: c.ClientSecret != "", GroupsClaim: c.GroupsClaim, TrustEmail: c.TrustEmail,
		AllowedOrgs: strings.Join(c.AllowedOrgs, " "), SAMLIdPMetadata: c.SAMLIdPMetadata, SAMLSPCert: c.SAMLSPCert,
		SAMLEmailAttr: c.SAMLEmailAttr, SAMLNameAttr: c.SAMLNameAttr, SAMLGroupsAttr: c.SAMLGroupsAttr, Managed: c.Managed, Created: c.Created}
	if c.Kind == identity.KindOIDC {
		v.ExtraScopes = strings.Join(extraScopes(c.Preset, c.Scopes), " ")
	}
	s.fillConnURLs(&v)
	return v
}

func (s *Server) fillConnURLs(v *connView) {
	v.RedirectURI = s.abs("/auth/oidc/callback")
	if v.Slug == "" {
		return
	}
	switch v.Kind {
	case identity.KindSAML:
		v.EntityID = s.abs("/auth/saml/" + v.Slug + "/metadata")
		v.MetadataURL = v.EntityID
		v.ACSURL = s.abs("/auth/saml/" + v.Slug + "/acs")
		v.TestURL = "/auth/saml/" + v.Slug + "/start"
	default:
		v.TestURL = "/auth/oidc/" + v.Slug + "/start"
		if v.Kind == identity.KindOIDC {
			v.BackchannelURL = s.abs("/auth/oidc/" + v.Slug + "/backchannel-logout")
		}
	}
}

// extraScopes returns the scopes beyond the preset's defaults.
func extraScopes(preset string, scopes []string) []string {
	base := map[string]bool{}
	for _, sc := range oidcrp.PresetFor(preset).Scopes {
		base[sc] = true
	}
	var out []string
	for _, sc := range scopes {
		if !base[sc] {
			out = append(out, sc)
		}
	}
	return out
}

type connListData struct {
	Scope       connScope
	Conns       []connView
	RedirectURI string
}

type connEditData struct {
	Scope       connScope
	Conn        connView
	New         bool
	MetadataURL string // the form's metadata URL field, echoed on error
	Mappings    []identity.GroupMapping
	CanOwner    bool
}

func (s *Server) connTitle(sc connScope) string {
	if sc.Platform {
		return "Platform sign-in connections"
	}
	return "Single sign-on"
}

func (s *Server) handleConnList(w http.ResponseWriter, r *http.Request, sc connScope) {
	conns, err := s.IDs.Connections(r.Context(), sc.OrgID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := connListData{Scope: sc, RedirectURI: s.abs("/auth/oidc/callback")}
	for _, c := range conns {
		d.Conns = append(d.Conns, s.viewConn(c))
	}
	s.render(w, r, http.StatusOK, "org_sso", Page{Title: s.connTitle(sc), Active: sc.Active, Data: d})
}

func validKind(k string) bool {
	return k == identity.KindOIDC || k == identity.KindGitHub || k == identity.KindSAML
}

func (s *Server) handleConnNew(w http.ResponseWriter, r *http.Request, sc connScope) {
	kind := r.URL.Query().Get("kind")
	if !validKind(kind) {
		kind = identity.KindOIDC
	}
	v := connView{Kind: kind, Enabled: true, Preset: "generic"}
	if p := r.URL.Query().Get("preset"); kind == identity.KindOIDC {
		if _, ok := oidcrp.Presets[p]; ok {
			v.Preset = p
		}
	}
	s.fillConnURLs(&v)
	s.render(w, r, http.StatusOK, "org_sso_edit", Page{Title: "New connection", Active: sc.Active, Data: connEditData{Scope: sc, Conn: v, New: true}})
}

// connForm reads the connection fields for kind from the form into c.
// Secrets go into c but never back into the view. It returns a message for
// the admin when a field is unusable.
func connForm(r *http.Request, c *identity.Connection, platform bool) string {
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	c.Name = f("name")
	c.Enabled = r.PostFormValue("enabled") != ""
	c.TrustEmail = platform && r.PostFormValue("trust_email") != ""
	if c.Name == "" || len(c.Name) > 100 {
		return "Enter a name of up to 100 characters."
	}
	switch c.Kind {
	case identity.KindOIDC:
		c.Preset = f("preset")
		if _, ok := oidcrp.Presets[c.Preset]; !ok {
			return "Choose a provider."
		}
		c.Issuer = f("issuer") // kept exactly: the ID token iss must match
		if !strings.HasPrefix(c.Issuer, "https://") || len(c.Issuer) <= len("https://") || strings.ContainsAny(c.Issuer, " {}") {
			return "Enter the issuer URL. It must start with https:// and have no {placeholders} left."
		}
		c.ClientID, c.ClientSecret = f("client_id"), f("client_secret")
		if c.ClientID == "" {
			return "Enter the client ID."
		}
		c.GroupsClaim = f("groups_claim")
		c.Scopes = nil
		if extra := strings.Fields(r.PostFormValue("scopes")); len(extra) > 0 {
			c.Scopes = append(append([]string{}, oidcrp.PresetFor(c.Preset).Scopes...), extraScopes(c.Preset, extra)...)
		}
	case identity.KindGitHub:
		c.Preset = ""
		c.Issuer = strings.TrimSuffix(f("issuer"), "/")
		if c.Issuer != "" && (!strings.HasPrefix(c.Issuer, "https://") || len(c.Issuer) <= len("https://")) {
			return "The GitHub Enterprise Server URL must start with https://."
		}
		c.ClientID, c.ClientSecret = f("client_id"), f("client_secret")
		if c.ClientID == "" {
			return "Enter the client ID."
		}
		c.AllowedOrgs = strings.Fields(r.PostFormValue("allowed_orgs"))
	case identity.KindSAML:
		c.Preset, c.Issuer = "", ""
		c.SAMLEmailAttr, c.SAMLNameAttr, c.SAMLGroupsAttr = f("email_attr"), f("name_attr"), f("groups_attr")
	}
	return ""
}

// samlMetadata resolves the metadata from the URL field (fetched with the
// SSRF-safe client) or the pasted XML. keep is used when both are empty.
func (s *Server) samlMetadata(r *http.Request, keep string) (string, string) {
	if u := strings.TrimSpace(r.PostFormValue("metadata_url")); u != "" {
		doc, err := samlsp.FetchIdPMetadata(r.Context(), s.HTTP, u)
		if err != nil {
			return "", "Could not use the metadata URL: " + err.Error()
		}
		return doc, ""
	}
	doc := strings.TrimSpace(r.PostFormValue("metadata"))
	if doc == "" {
		if keep != "" {
			return keep, ""
		}
		return "", "Paste the identity provider's metadata XML or enter its https metadata URL."
	}
	if err := samlsp.ValidateIdPMetadata(doc); err != nil {
		return "", "The metadata is not usable: " + err.Error()
	}
	return doc, ""
}

func (s *Server) connFormError(w http.ResponseWriter, r *http.Request, sc connScope, c identity.Connection, isNew bool, msg string) {
	c.ClientSecret, c.SAMLSPKey = "", ""
	v := s.viewConn(c)
	if v.SAMLIdPMetadata == "" {
		v.SAMLIdPMetadata = r.PostFormValue("metadata")
	}
	d := connEditData{Scope: sc, Conn: v, New: isNew, MetadataURL: r.PostFormValue("metadata_url")}
	if !isNew && !sc.Platform {
		d.Mappings, d.CanOwner = s.connMappings(r, c.ID), orgFrom(r.Context()).Role >= identity.RoleOwner
	}
	s.render(w, r, http.StatusBadRequest, "org_sso_edit", Page{Title: "Connection", Active: sc.Active, Error: msg, Data: d})
}

// connSlug is {orgslug}-{name} for org connections and {name} for platform
// ones, cut to the slug length limit.
func connSlug(sc connScope, name string, n int) string {
	base := identity.Slugify(name)
	if sc.OrgSlug != "" {
		base = sc.OrgSlug + "-" + base
	}
	suffix := ""
	if n > 1 {
		suffix = "-" + strconv.Itoa(n)
	}
	if len(base)+len(suffix) > 40 {
		base = base[:40-len(suffix)]
	}
	return strings.Trim(base, "-") + suffix
}

func (s *Server) handleConnCreate(w http.ResponseWriter, r *http.Request, sc connScope) {
	c := identity.Connection{OrgID: sc.OrgID, Kind: r.PostFormValue("kind")}
	if !validKind(c.Kind) {
		s.renderError(w, r, http.StatusBadRequest, "Unknown connection type.")
		return
	}
	if msg := connForm(r, &c, sc.Platform); msg != "" {
		s.connFormError(w, r, sc, c, true, msg)
		return
	}
	if c.Kind != identity.KindSAML && c.ClientSecret == "" {
		s.connFormError(w, r, sc, c, true, "Enter the client secret.")
		return
	}
	if c.Kind == identity.KindSAML {
		doc, msg := s.samlMetadata(r, "")
		if msg != "" {
			s.connFormError(w, r, sc, c, true, msg)
			return
		}
		c.SAMLIdPMetadata = doc
	}
	var saved identity.Connection
	var err error
	for n := 1; n <= 20; n++ {
		c.Slug = connSlug(sc, c.Name, n)
		if _, e := s.IDs.ConnectionBySlug(r.Context(), c.Slug); e == nil {
			err = identity.ErrConflict
			continue
		}
		if c.Kind == identity.KindSAML {
			c.SAMLSPKey, c.SAMLSPCert, err = samlsp.NewKeyPair(s.abs("/auth/saml/" + c.Slug + "/metadata"))
			if err != nil {
				s.serverError(w, r, err)
				return
			}
		}
		saved, err = s.IDs.SaveConnection(r.Context(), c)
		if !errors.Is(err, identity.ErrConflict) {
			break
		}
	}
	switch {
	case errors.Is(err, identity.ErrInvalid):
		s.connFormError(w, r, sc, c, true, "Check the fields and try again.")
		return
	case errors.Is(err, identity.ErrConflict):
		s.connFormError(w, r, sc, c, true, "Choose a different name.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.audit(r, sc.OrgID, "connection.create", saved.Slug, connDetail(saved))
	redirectFlash(w, r, sc.Base+"/"+strconv.FormatInt(saved.ID, 10), "Created "+saved.Name+". Give your identity provider admin the values below.")
}

// connDetail is the audit detail for a connection: labels only, no secrets.
func connDetail(c identity.Connection) string {
	d := fmt.Sprintf("kind=%s enabled=%t", c.Kind, c.Enabled)
	if c.Preset != "" {
		d += " preset=" + c.Preset
	}
	if c.TrustEmail {
		d += " trust_email=true"
	}
	return d
}

// loadConn fetches a connection within the scope; anything else is 404.
func (s *Server) loadConn(w http.ResponseWriter, r *http.Request, sc connScope) (identity.Connection, bool) {
	id := pathInt(r, "id")
	c, err := s.IDs.OrgConnection(r.Context(), sc.OrgID, id)
	if id == 0 || errors.Is(err, identity.ErrNotFound) {
		s.notFound(w, r)
		return c, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return c, false
	}
	return c, true
}

func (s *Server) connMappings(r *http.Request, connID int64) []identity.GroupMapping {
	all, err := s.IDs.GroupMappings(r.Context(), orgFrom(r.Context()).Org.ID)
	if err != nil {
		return nil
	}
	var out []identity.GroupMapping
	for _, m := range all {
		if m.Source == identity.SourceSSO && m.ConnectionID == connID {
			out = append(out, m)
		}
	}
	return out
}

func (s *Server) handleConnEdit(w http.ResponseWriter, r *http.Request, sc connScope) {
	c, ok := s.loadConn(w, r, sc)
	if !ok {
		return
	}
	d := connEditData{Scope: sc, Conn: s.viewConn(c)}
	if !sc.Platform {
		d.Mappings, d.CanOwner = s.connMappings(r, c.ID), orgFrom(r.Context()).Role >= identity.RoleOwner
	}
	s.render(w, r, http.StatusOK, "org_sso_edit", Page{Title: c.Name, Active: sc.Active, Data: d})
}

func (s *Server) forget(issuers ...string) {
	if s.RP == nil {
		return
	}
	for _, i := range issuers {
		if i != "" {
			s.RP.Forget(i)
		}
	}
}

func (s *Server) handleConnUpdate(w http.ResponseWriter, r *http.Request, sc connScope) {
	old, ok := s.loadConn(w, r, sc)
	if !ok {
		return
	}
	if old.Managed {
		s.renderError(w, r, http.StatusForbidden, "This connection is declared in the providers file and cannot be changed here.")
		return
	}
	c := identity.Connection{ID: old.ID, OrgID: sc.OrgID, Slug: old.Slug, Kind: old.Kind}
	if msg := connForm(r, &c, sc.Platform); msg != "" {
		s.connFormError(w, r, sc, c, false, msg)
		return
	}
	if c.Kind == identity.KindSAML {
		doc, msg := s.samlMetadata(r, old.SAMLIdPMetadata)
		if msg != "" {
			s.connFormError(w, r, sc, c, false, msg)
			return
		}
		c.SAMLIdPMetadata = doc
	}
	saved, err := s.IDs.SaveConnection(r.Context(), c)
	switch {
	case errors.Is(err, identity.ErrNotFound):
		s.notFound(w, r)
		return
	case errors.Is(err, identity.ErrInvalid):
		s.connFormError(w, r, sc, c, false, "Check the fields and try again.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.forget(old.Issuer, saved.Issuer)
	msg := "Saved."
	if old.Enabled && !saved.Enabled {
		if err := s.IDs.DeleteConnectionSessions(r.Context(), saved.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
		msg = "Saved. The connection is disabled and its sessions have ended."
	}
	detail := connDetail(saved)
	if c.ClientSecret != "" {
		detail += " secret_changed=true"
	}
	s.audit(r, sc.OrgID, "connection.update", saved.Slug, detail)
	redirectFlash(w, r, sc.Base+"/"+strconv.FormatInt(saved.ID, 10), msg)
}

func (s *Server) handleConnDelete(w http.ResponseWriter, r *http.Request, sc connScope) {
	c, ok := s.loadConn(w, r, sc)
	if !ok {
		return
	}
	if c.Managed {
		s.renderError(w, r, http.StatusForbidden, "This connection is declared in the providers file. Remove it there.")
		return
	}
	// Sessions first: their connection_id is set to NULL when the
	// connection row goes, after which they can no longer be found.
	if err := s.IDs.DeleteConnectionSessions(r.Context(), c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.IDs.DeleteConnection(r.Context(), sc.OrgID, c.ID); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.forget(c.Issuer)
	s.audit(r, sc.OrgID, "connection.delete", c.Slug, "kind="+c.Kind)
	redirectFlash(w, r, sc.Base, "Deleted "+c.Name+".")
}

// --- group mappings ---

// mappingFromForm parses group and role, refusing owner unless the viewer
// is an owner.
func mappingFromForm(r *http.Request) (identity.GroupMapping, string) {
	oc := orgFrom(r.Context())
	m := identity.GroupMapping{OrgID: oc.Org.ID, Group: strings.TrimSpace(r.PostFormValue("group")), Role: identity.ParseRole(r.PostFormValue("role"))}
	if m.Group == "" || len(m.Group) > 256 {
		return m, "Enter a group name or ID of up to 256 characters."
	}
	if m.Role == identity.RoleNone {
		return m, "Choose a role."
	}
	if m.Role == identity.RoleOwner && oc.Role < identity.RoleOwner {
		return m, "Only owners can map a group to the owner role."
	}
	return m, ""
}

func (s *Server) handleSSOMappingAdd(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	sc := orgScope(r)
	c, ok := s.loadConn(w, r, sc)
	if !ok {
		return
	}
	back := sc.Base + "/" + strconv.FormatInt(c.ID, 10)
	m, msg := mappingFromForm(r)
	if msg != "" {
		redirectFlash(w, r, back, msg)
		return
	}
	m.Source, m.ConnectionID = identity.SourceSSO, c.ID
	m, err := s.IDs.AddGroupMapping(r.Context(), m)
	if errors.Is(err, identity.ErrConflict) {
		redirectFlash(w, r, back, "That group already has a mapping.")
		return
	}
	if errors.Is(err, identity.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "mapping.add", c.Slug, "source=sso group="+m.Group+" role="+m.Role.String())
	redirectFlash(w, r, back, "Added the mapping.")
}

// deleteMapping removes a mapping only if it belongs to this org and matches
// the source (and connection) the URL names.
func (s *Server) deleteMapping(w http.ResponseWriter, r *http.Request, source string, connID int64, back, target string) {
	oc := orgFrom(r.Context())
	mid := pathInt(r, "mid")
	all, err := s.IDs.GroupMappings(r.Context(), oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var found *identity.GroupMapping
	for i := range all {
		if all[i].ID == mid && all[i].Source == source && all[i].ConnectionID == connID {
			found = &all[i]
		}
	}
	if found == nil {
		s.notFound(w, r)
		return
	}
	if found.Role == identity.RoleOwner && oc.Role < identity.RoleOwner {
		redirectFlash(w, r, back, "Only owners can remove a mapping to the owner role.")
		return
	}
	if err := s.IDs.DeleteGroupMapping(r.Context(), oc.Org.ID, mid); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "mapping.delete", target, "source="+source+" group="+found.Group+" role="+found.Role.String())
	redirectFlash(w, r, back, "Removed the mapping.")
}

func (s *Server) handleSSOMappingDelete(w http.ResponseWriter, r *http.Request) {
	sc := orgScope(r)
	c, ok := s.loadConn(w, r, sc)
	if !ok {
		return
	}
	s.deleteMapping(w, r, identity.SourceSSO, c.ID, sc.Base+"/"+strconv.FormatInt(c.ID, 10), c.Slug)
}

// --- SCIM ---

type scimData struct {
	BaseURL  string
	Tokens   []identity.SCIMToken
	Secret   string // raw token, only in the create response
	Mappings []identity.GroupMapping
	CanOwner bool
}

func (s *Server) scimPage(w http.ResponseWriter, r *http.Request, status int, secret, errMsg string) {
	oc := orgFrom(r.Context())
	toks, err := s.IDs.SCIMTokens(r.Context(), oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	all, err := s.IDs.GroupMappings(r.Context(), oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := scimData{BaseURL: s.abs("/scim/v2"), Tokens: toks, Secret: secret, CanOwner: oc.Role >= identity.RoleOwner}
	for _, m := range all {
		if m.Source == identity.SourceSCIM {
			d.Mappings = append(d.Mappings, m)
		}
	}
	s.render(w, r, status, "org_scim", Page{Title: "SCIM provisioning", Active: "scim", Error: errMsg, Data: d})
}

func (s *Server) handleSCIM(w http.ResponseWriter, r *http.Request) {
	s.scimPage(w, r, http.StatusOK, "", "")
}

func (s *Server) handleSCIMTokenCreate(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	tok, raw, err := s.IDs.CreateSCIMToken(r.Context(), oc.Org.ID, r.PostFormValue("label"))
	if errors.Is(err, identity.ErrInvalid) {
		s.scimPage(w, r, http.StatusBadRequest, "", "Enter a label of up to 100 characters.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "scim_token.create", tok.Prefix, tok.Label)
	// The raw token is rendered in this response only; it is stored hashed.
	s.scimPage(w, r, http.StatusOK, raw, "")
}

func (s *Server) handleSCIMTokenRevoke(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	id := pathInt(r, "id")
	if err := s.IDs.RevokeSCIMToken(r.Context(), oc.Org.ID, id); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "scim_token.revoke", strconv.FormatInt(id, 10), "")
	redirectFlash(w, r, "/console/orgs/"+oc.Org.Slug+"/scim", "Revoked the token.")
}

func (s *Server) handleSCIMMappingAdd(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	back := "/console/orgs/" + oc.Org.Slug + "/scim"
	m, msg := mappingFromForm(r)
	if msg != "" {
		redirectFlash(w, r, back, msg)
		return
	}
	m.Source = identity.SourceSCIM
	m, err := s.IDs.AddGroupMapping(r.Context(), m)
	if errors.Is(err, identity.ErrConflict) {
		redirectFlash(w, r, back, "That group already has a mapping.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "mapping.add", "scim", "source=scim group="+m.Group+" role="+m.Role.String())
	redirectFlash(w, r, back, "Added the mapping.")
}

func (s *Server) handleSCIMMappingDelete(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	s.deleteMapping(w, r, identity.SourceSCIM, 0, "/console/orgs/"+oc.Org.Slug+"/scim", "scim")
}

// --- OAuth (JWT) issuers ---

type issuerForm struct {
	ID              int64
	Issuer          string
	Audience        string
	JWKSURL         string
	ScopePrefix     string
	AllowedSubjects string
	Enabled         bool
}

type issuersData struct {
	Issuers []identity.JWTIssuer
	Form    issuerForm
	APIBase string
}

func issuerToForm(j identity.JWTIssuer) issuerForm {
	return issuerForm{ID: j.ID, Issuer: j.Issuer, Audience: j.Audience, JWKSURL: j.JWKSURL, ScopePrefix: j.ScopePrefix,
		AllowedSubjects: strings.Join(j.AllowedSubjects, "\n"), Enabled: j.Enabled}
}

// readIssuer parses the issuer form. The org comes from the context.
func readIssuer(r *http.Request) (identity.JWTIssuer, issuerForm, string) {
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	j := identity.JWTIssuer{OrgID: orgFrom(r.Context()).Org.ID, Issuer: f("issuer"), Audience: f("audience"), JWKSURL: f("jwks_url"),
		ScopePrefix: f("scope_prefix"), AllowedSubjects: strings.Fields(r.PostFormValue("allowed_subjects")), Enabled: r.PostFormValue("enabled") != ""}
	form := issuerForm{Issuer: j.Issuer, Audience: j.Audience, JWKSURL: j.JWKSURL, ScopePrefix: j.ScopePrefix,
		AllowedSubjects: strings.Join(j.AllowedSubjects, "\n"), Enabled: j.Enabled}
	switch {
	case !strings.HasPrefix(j.Issuer, "https://") || len(j.Issuer) <= len("https://"):
		return j, form, "The issuer must be an https URL."
	case j.Audience == "" || len(j.Audience) > 512:
		return j, form, "Enter the audience your tokens carry in aud."
	case j.JWKSURL != "" && !strings.HasPrefix(j.JWKSURL, "https://"):
		return j, form, "The JWKS URL must be an https URL, or leave it blank to use discovery."
	case len(j.ScopePrefix) > 64 || strings.ContainsAny(j.ScopePrefix, " \t\r\n"):
		return j, form, "The scope prefix can be up to 64 characters with no spaces."
	}
	return j, form, ""
}

func issuerErr(err error) string {
	switch {
	case errors.Is(err, identity.ErrConflict):
		return "That issuer and audience are already registered."
	case errors.Is(err, identity.ErrInvalid):
		return "Check the fields and try again."
	}
	return ""
}

func issuerDetail(j identity.JWTIssuer) string {
	return fmt.Sprintf("audience=%s enabled=%t subjects=%d", j.Audience, j.Enabled, len(j.AllowedSubjects))
}

func (s *Server) issuersPage(w http.ResponseWriter, r *http.Request, status int, form issuerForm, errMsg string) {
	oc := orgFrom(r.Context())
	list, err := s.IDs.JWTIssuers(r.Context(), oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "org_tokens", Page{Title: "OAuth tokens", Active: "tokens", Error: errMsg,
		Data: issuersData{Issuers: list, Form: form, APIBase: s.Cfg.PublicURL}})
}

func (s *Server) handleIssuers(w http.ResponseWriter, r *http.Request) {
	s.issuersPage(w, r, http.StatusOK, issuerForm{Enabled: true}, "")
}

func (s *Server) handleIssuerCreate(w http.ResponseWriter, r *http.Request) {
	j, form, msg := readIssuer(r)
	if msg != "" {
		s.issuersPage(w, r, http.StatusBadRequest, form, msg)
		return
	}
	saved, err := s.IDs.SaveJWTIssuer(r.Context(), j)
	if m := issuerErr(err); m != "" {
		s.issuersPage(w, r, http.StatusBadRequest, form, m)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, j.OrgID, "jwt_issuer.create", saved.Issuer, issuerDetail(saved))
	redirectFlash(w, r, "/console/orgs/"+orgFrom(r.Context()).Org.Slug+"/tokens", "Registered "+saved.Issuer+".")
}

func (s *Server) loadIssuer(w http.ResponseWriter, r *http.Request) (identity.JWTIssuer, bool) {
	id := pathInt(r, "id")
	j, err := s.IDs.OrgJWTIssuer(r.Context(), orgFrom(r.Context()).Org.ID, id)
	if id == 0 || errors.Is(err, identity.ErrNotFound) {
		s.notFound(w, r)
		return j, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return j, false
	}
	return j, true
}

func (s *Server) handleIssuerEdit(w http.ResponseWriter, r *http.Request) {
	j, ok := s.loadIssuer(w, r)
	if !ok {
		return
	}
	s.issuersPage(w, r, http.StatusOK, issuerToForm(j), "")
}

func (s *Server) handleIssuerUpdate(w http.ResponseWriter, r *http.Request) {
	old, ok := s.loadIssuer(w, r)
	if !ok {
		return
	}
	j, form, msg := readIssuer(r)
	j.ID, form.ID = old.ID, old.ID
	if msg == "" {
		var saved identity.JWTIssuer
		var err error
		saved, err = s.IDs.SaveJWTIssuer(r.Context(), j)
		if msg = issuerErr(err); msg == "" {
			if errors.Is(err, identity.ErrNotFound) {
				s.notFound(w, r)
				return
			}
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			s.audit(r, j.OrgID, "jwt_issuer.update", saved.Issuer, issuerDetail(saved))
			redirectFlash(w, r, "/console/orgs/"+orgFrom(r.Context()).Org.Slug+"/tokens", "Saved.")
			return
		}
	}
	s.issuersPage(w, r, http.StatusBadRequest, form, msg)
}

func (s *Server) handleIssuerDelete(w http.ResponseWriter, r *http.Request) {
	j, ok := s.loadIssuer(w, r)
	if !ok {
		return
	}
	if err := s.IDs.DeleteJWTIssuer(r.Context(), j.OrgID, j.ID); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit(r, j.OrgID, "jwt_issuer.delete", j.Issuer, "audience="+j.Audience)
	redirectFlash(w, r, "/console/orgs/"+orgFrom(r.Context()).Org.Slug+"/tokens", "Removed "+j.Issuer+".")
}
