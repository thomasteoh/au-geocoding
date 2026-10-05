package console

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
)

// registerOrgCoreRoutes mounts keys, members, invites, domains, audit and
// settings pages. Every handler takes the org from the request context and
// passes its ID to the store, so an object ID from another org is not found
// (auth.md A5).
func (s *Server) registerOrgCoreRoutes(mux *http.ServeMux) {
	const p = "/console/orgs/{org}"
	mux.Handle("GET "+p+"/keys", s.orgRoute(identity.RoleViewer, s.handleKeys))
	mux.Handle("POST "+p+"/keys", s.orgPost(identity.RoleDeveloper, s.handleKeyCreate))
	mux.Handle("POST "+p+"/keys/{id}/revoke", s.orgPost(identity.RoleDeveloper, s.handleKeyRevoke))

	mux.Handle("GET "+p+"/members", s.orgRoute(identity.RoleViewer, s.handleMembers))
	mux.Handle("POST "+p+"/members/leave", s.orgPost(identity.RoleViewer, s.handleLeave))
	mux.Handle("POST "+p+"/members/{user}/role", s.orgPost(identity.RoleAdmin, s.handleMemberRole))
	mux.Handle("POST "+p+"/members/{user}/remove", s.orgPost(identity.RoleAdmin, s.handleMemberRemove))
	mux.Handle("POST "+p+"/invites", s.orgPost(identity.RoleAdmin, s.handleInviteCreate))
	mux.Handle("POST "+p+"/invites/{id}/delete", s.orgPost(identity.RoleAdmin, s.handleInviteDelete))

	mux.Handle("GET "+p+"/domains", s.orgRoute(identity.RoleAdmin, s.handleDomains))
	mux.Handle("POST "+p+"/domains", s.orgPost(identity.RoleAdmin, s.handleDomainAdd))
	mux.Handle("POST "+p+"/domains/{id}/verify", s.orgPost(identity.RoleAdmin, s.handleDomainVerify))
	mux.Handle("POST "+p+"/domains/{id}/delete", s.orgPost(identity.RoleAdmin, s.handleDomainDelete))

	mux.Handle("GET "+p+"/audit", s.orgRoute(identity.RoleAdmin, s.handleAudit))

	mux.Handle("GET "+p+"/settings", s.orgRoute(identity.RoleOwner, s.handleSettings))
	mux.Handle("POST "+p+"/settings", s.orgPost(identity.RoleOwner, s.handleSettingsSave))
	mux.Handle("POST "+p+"/settings/delete", s.orgPost(identity.RoleOwner, s.handleOrgDelete))
}

func orgPath(oc *OrgContext, page string) string {
	return "/console/orgs/" + oc.Org.Slug + "/" + page
}

func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotFound, "Not found.")
}

// --- API keys ---

// keyScopes are the scopes a console key can carry.
var keyScopes = []string{"search", "batch"}

type keyRow struct {
	publicapi.Key
	CreatedByEmail string
	CanRevoke      bool
	Expired        bool
}

type keysData struct {
	Keys      []keyRow
	Scopes    []string
	NewKey    string // raw value, set only on the create response
	NewKeyRow *keyRow
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	s.renderKeys(w, r, "", nil)
}

func (s *Server) renderKeys(w http.ResponseWriter, r *http.Request, raw string, created *publicapi.Key) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	keys, err := s.Keys.OrgKeys(oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	emails := map[int64]string{}
	if members, err := s.IDs.Members(r.Context(), oc.Org.ID); err == nil {
		for _, m := range members {
			emails[m.User.ID] = m.User.Email
		}
	}
	now := time.Now()
	d := keysData{Scopes: keyScopes, NewKey: raw}
	for _, k := range keys {
		row := keyRow{Key: k, Expired: k.Expires != nil && k.Expires.Before(now)}
		if k.CreatedBy != 0 {
			e, ok := emails[k.CreatedBy]
			if !ok {
				if u, err := s.IDs.UserByID(r.Context(), k.CreatedBy); err == nil {
					e = u.Email
				}
				emails[k.CreatedBy] = e
			}
			row.CreatedByEmail = e
		}
		row.CanRevoke = k.Revoked == nil && (oc.Role >= identity.RoleAdmin || oc.Role >= identity.RoleDeveloper && k.CreatedBy == v.User.ID)
		if created != nil && k.ID == created.ID {
			nr := row
			d.NewKeyRow = &nr
		}
		d.Keys = append(d.Keys, row)
	}
	s.render(w, r, http.StatusOK, "org_keys", Page{Title: "API keys", Active: "keys", Data: d})
}

func (s *Server) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	back := orgPath(oc, "keys")
	label := strings.TrimSpace(r.PostFormValue("label"))
	if label == "" || utf8.RuneCountInString(label) > 100 {
		redirectFlash(w, r, back, "Enter a label of up to 100 characters.")
		return
	}
	var scopes []string
	for _, sc := range keyScopes {
		for _, got := range r.PostForm["scope"] {
			if got == sc {
				scopes = append(scopes, sc)
				break
			}
		}
	}
	if len(scopes) == 0 {
		redirectFlash(w, r, back, "Choose at least one scope.")
		return
	}
	for _, sc := range scopes {
		if sc == "batch" && oc.Org.Tier != "batch" {
			redirectFlash(w, r, back, "The batch scope needs the batch tier. Ask a platform admin to change your tier.")
			return
		}
	}
	var expires *time.Time
	if ds := strings.TrimSpace(r.PostFormValue("expires_days")); ds != "" {
		n, err := strconv.Atoi(ds)
		if err != nil || n < 1 || n > 730 {
			redirectFlash(w, r, back, "Expiry must be between 1 and 730 days, or empty for no expiry.")
			return
		}
		t := time.Now().UTC().Add(time.Duration(n) * 24 * time.Hour).Truncate(time.Second)
		expires = &t
	}
	k, raw, err := s.Keys.IssueKeyWith(publicapi.IssueOptions{Label: label, Tier: publicapi.QuotaTier(oc.Org.Tier), Scopes: scopes,
		OrgID: oc.Org.ID, CreatedBy: v.User.ID, Expires: expires})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "key.create", label+" ("+k.Prefix+")", "scopes="+strings.Join(scopes, " "))
	// No redirect: the raw key is shown in this response and never again.
	s.renderKeys(w, r, raw, &k)
}

func (s *Server) handleKeyRevoke(w http.ResponseWriter, r *http.Request) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	k, err := s.Keys.OrgKey(oc.Org.ID, id)
	if errors.Is(err, publicapi.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if oc.Role < identity.RoleAdmin && k.CreatedBy != v.User.ID {
		s.renderError(w, r, http.StatusForbidden, "Developers can revoke only keys they created.")
		return
	}
	if k.Revoked != nil {
		redirectFlash(w, r, orgPath(oc, "keys"), "That key is already revoked.")
		return
	}
	if err := s.Keys.RevokeOrgKey(oc.Org.ID, k.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "key.revoke", k.Label+" ("+k.Prefix+")", "")
	redirectFlash(w, r, orgPath(oc, "keys"), "Revoked "+k.Label+".")
}

// --- members and invites ---

type memberRow struct {
	identity.Membership
	Self      bool
	CanManage bool
}

type membersData struct {
	Members   []memberRow
	Invites   []identity.Invite
	Grantable []identity.Role // roles the viewer may assign
}

// canManage reports whether actor may change or remove a member holding
// target: owners manage anyone, admins manage viewer/developer/admin.
func canManage(actor, target identity.Role) bool {
	return actor >= identity.RoleAdmin && (target < identity.RoleOwner || actor >= identity.RoleOwner)
}

func grantable(actor identity.Role) []identity.Role {
	var out []identity.Role
	for _, r := range identity.AllRoles {
		if r <= identity.RoleAdmin || actor >= identity.RoleOwner {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	members, err := s.IDs.Members(r.Context(), oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := membersData{Grantable: grantable(oc.Role)}
	for _, m := range members {
		self := m.User.ID == v.User.ID
		d.Members = append(d.Members, memberRow{Membership: m, Self: self, CanManage: !self && canManage(oc.Role, m.Role)})
	}
	if oc.Role >= identity.RoleAdmin {
		if d.Invites, err = s.IDs.Invites(r.Context(), oc.Org.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "org_members", Page{Title: "Members", Active: "members", Data: d})
}

// orgMember finds a member of the context org by the {user} path value.
func (s *Server) orgMember(r *http.Request) (identity.Membership, bool, error) {
	oc := orgFrom(r.Context())
	id, ok := pathID(r, "user")
	if !ok {
		return identity.Membership{}, false, nil
	}
	members, err := s.IDs.Members(r.Context(), oc.Org.ID)
	if err != nil {
		return identity.Membership{}, false, err
	}
	for _, m := range members {
		if m.User.ID == id {
			return m, true, nil
		}
	}
	return identity.Membership{}, false, nil
}

func (s *Server) handleMemberRole(w http.ResponseWriter, r *http.Request) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	back := orgPath(oc, "members")
	m, ok, err := s.orgMember(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.notFound(w, r)
		return
	}
	role := identity.ParseRole(r.PostFormValue("role"))
	if role == identity.RoleNone {
		redirectFlash(w, r, back, "Choose a role.")
		return
	}
	if m.User.ID == v.User.ID {
		redirectFlash(w, r, back, "You can't change your own role.")
		return
	}
	if !canManage(oc.Role, m.Role) || !canManage(oc.Role, role) {
		s.renderError(w, r, http.StatusForbidden, "Only owners can grant or change the owner role.")
		return
	}
	if role == m.Role {
		redirectFlash(w, r, back, m.User.Email+" is already "+role.String()+".")
		return
	}
	err = s.IDs.SetMembership(r.Context(), oc.Org.ID, m.User.ID, role, m.Source)
	if errors.Is(err, identity.ErrLastOwner) {
		redirectFlash(w, r, back, "An organisation must keep at least one owner.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "member.role", m.User.Email, m.Role.String()+" -> "+role.String())
	redirectFlash(w, r, back, m.User.Email+" is now "+role.String()+".")
}

func (s *Server) handleMemberRemove(w http.ResponseWriter, r *http.Request) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	back := orgPath(oc, "members")
	m, ok, err := s.orgMember(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.notFound(w, r)
		return
	}
	if m.User.ID == v.User.ID {
		redirectFlash(w, r, back, "Use \"Leave organisation\" to remove yourself.")
		return
	}
	if !canManage(oc.Role, m.Role) {
		s.renderError(w, r, http.StatusForbidden, "Only owners can remove an owner.")
		return
	}
	err = s.IDs.RemoveMember(r.Context(), oc.Org.ID, m.User.ID)
	switch {
	case errors.Is(err, identity.ErrLastOwner):
		redirectFlash(w, r, back, "An organisation must keep at least one owner.")
		return
	case errors.Is(err, identity.ErrNotFound):
		s.notFound(w, r)
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "member.remove", m.User.Email, "")
	redirectFlash(w, r, back, "Removed "+m.User.Email+".")
}

func (s *Server) handleLeave(w http.ResponseWriter, r *http.Request) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	back := orgPath(oc, "members")
	err := s.IDs.RemoveMember(r.Context(), oc.Org.ID, v.User.ID)
	switch {
	case errors.Is(err, identity.ErrLastOwner):
		redirectFlash(w, r, back, "You are the last owner. Make someone else an owner before you leave.")
		return
	case errors.Is(err, identity.ErrNotFound):
		redirectFlash(w, r, back, "You are not a member of this organisation.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "member.remove", v.User.Email, "left")
	redirectFlash(w, r, "/console?all=1", "You left "+oc.Org.Name+".")
}

// inviteTTL is how long an invite stays valid.
const inviteTTL = 14 * 24 * time.Hour

func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	oc, v := orgFrom(r.Context()), viewerFrom(r.Context())
	back := orgPath(oc, "members")
	email := identity.NormaliseEmail(r.PostFormValue("email"))
	role := identity.ParseRole(r.PostFormValue("role"))
	if !identity.ValidEmail(email) || role == identity.RoleNone {
		redirectFlash(w, r, back, "Enter an email address and choose a role.")
		return
	}
	if !canManage(oc.Role, role) {
		s.renderError(w, r, http.StatusForbidden, "Only owners can invite owners.")
		return
	}
	// Existing accounts get a pending invite like anyone else: they accept it
	// by signing in, so nobody is added to an org without acting, and the
	// response never reveals whether an account exists.
	if u, err := s.IDs.UserByEmail(r.Context(), email); err == nil {
		if cur, err := s.IDs.Role(r.Context(), oc.Org.ID, u.ID); err == nil && cur != identity.RoleNone {
			redirectFlash(w, r, back, email+" is already a member.")
			return
		}
	}
	if err := s.IDs.CreateInvite(r.Context(), oc.Org.ID, email, role, v.User.ID, inviteTTL); err != nil {
		if errors.Is(err, identity.ErrInvalid) {
			redirectFlash(w, r, back, "Enter an email address and choose a role.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "invite.create", email, "role="+role.String())
	redirectFlash(w, r, back, "Invited "+email+". They join as "+role.String()+" when they next sign in.")
}

func (s *Server) handleInviteDelete(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return
	}
	var email string
	invites, err := s.IDs.Invites(r.Context(), oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, in := range invites {
		if in.ID == id {
			email = in.Email
		}
	}
	err = s.IDs.DeleteInvite(r.Context(), oc.Org.ID, id)
	if errors.Is(err, identity.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "invite.delete", email, "")
	redirectFlash(w, r, orgPath(oc, "members"), "Invite deleted.")
}

// --- domains ---

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	ds, err := s.IDs.Domains(r.Context(), oc.Org.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "org_domains", Page{Title: "Domains", Active: "domains", Data: ds})
}

func (s *Server) handleDomainAdd(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	back := orgPath(oc, "domains")
	d, err := s.IDs.AddDomain(r.Context(), oc.Org.ID, r.PostFormValue("domain"))
	switch {
	case errors.Is(err, identity.ErrInvalid):
		redirectFlash(w, r, back, "Enter a domain name such as example.com.")
		return
	case errors.Is(err, identity.ErrConflict):
		redirectFlash(w, r, back, "That domain is already on the list.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "domain.add", d.Domain, "")
	redirectFlash(w, r, back, "Added "+d.Domain+". Publish the TXT record below, then verify.")
}

// domainFromPath loads the {id} domain within the context org.
func (s *Server) domainFromPath(w http.ResponseWriter, r *http.Request) (identity.Domain, bool) {
	oc := orgFrom(r.Context())
	id, ok := pathID(r, "id")
	if !ok {
		s.notFound(w, r)
		return identity.Domain{}, false
	}
	d, err := s.IDs.OrgDomain(r.Context(), oc.Org.ID, id)
	if errors.Is(err, identity.ErrNotFound) {
		s.notFound(w, r)
		return d, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return d, false
	}
	return d, true
}

func txtMatches(records []string, want string) bool {
	for _, rec := range records {
		if strings.Trim(strings.TrimSpace(rec), `"' `) == want {
			return true
		}
	}
	return false
}

func (s *Server) handleDomainVerify(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	back := orgPath(oc, "domains")
	d, ok := s.domainFromPath(w, r)
	if !ok {
		return
	}
	if d.Verified != nil {
		redirectFlash(w, r, back, d.Domain+" is already verified.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	records, err := s.LookupTXT(ctx, d.TXTName())
	cancel()
	if err != nil || !txtMatches(records, d.TXTValue()) {
		redirectFlash(w, r, back, "No matching TXT record found at "+d.TXTName()+". DNS changes can take a while to appear; try again later.")
		return
	}
	err = s.IDs.MarkDomainVerified(r.Context(), oc.Org.ID, d.ID)
	switch {
	case errors.Is(err, identity.ErrConflict):
		redirectFlash(w, r, back, d.Domain+" is already verified by another organisation.")
		return
	case errors.Is(err, identity.ErrNotFound):
		s.notFound(w, r)
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "domain.verify", d.Domain, "")
	redirectFlash(w, r, back, "Verified "+d.Domain+".")
}

func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	d, ok := s.domainFromPath(w, r)
	if !ok {
		return
	}
	if err := s.IDs.DeleteDomain(r.Context(), oc.Org.ID, d.ID); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			s.notFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "domain.delete", d.Domain, "")
	redirectFlash(w, r, orgPath(oc, "domains"), "Removed "+d.Domain+".")
}

// --- audit log ---

const auditPageSize = 100

type auditData struct {
	Events []identity.AuditEvent
	Older  int64 // before= for the next page, 0 if none
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	events, err := s.IDs.AuditLog(r.Context(), oc.Org.ID, before, auditPageSize)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := auditData{Events: events}
	if len(events) == auditPageSize {
		d.Older = events[len(events)-1].ID
	}
	s.render(w, r, http.StatusOK, "org_audit", Page{Title: "Audit log", Active: "audit", Data: d})
}

// --- settings ---

type settingsData struct {
	DefaultRoles []identity.Role
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "org_settings", Page{Title: "Settings", Active: "settings",
		Data: settingsData{DefaultRoles: []identity.Role{identity.RoleViewer, identity.RoleDeveloper, identity.RoleAdmin}}})
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	back := orgPath(oc, "settings")
	set := identity.OrgSettings{
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		JITEnabled:  r.PostFormValue("jit") != "",
		SSOEnforced: r.PostFormValue("sso_enforced") != "",
		DefaultRole: identity.ParseRole(r.PostFormValue("default_role")),
	}
	if set.SSOEnforced && !oc.Org.SSOEnforced {
		ds, err := s.IDs.Domains(r.Context(), oc.Org.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		verified := false
		for _, d := range ds {
			verified = verified || d.Verified != nil
		}
		conns, err := s.IDs.OrgLoginConnections(r.Context(), oc.Org.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if !verified || len(conns) == 0 {
			redirectFlash(w, r, back, "To enforce single sign-on, first verify a domain and enable an SSO connection.")
			return
		}
	}
	err := s.IDs.UpdateOrgSettings(r.Context(), oc.Org.ID, set)
	if errors.Is(err, identity.ErrInvalid) {
		redirectFlash(w, r, back, "Enter a name of up to 100 characters and a default role of viewer, developer or admin.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, oc.Org.ID, "org.settings", oc.Org.Slug, fmt.Sprintf("name=%q jit=%t default_role=%s sso_enforced=%t",
		set.Name, set.JITEnabled, set.DefaultRole, set.SSOEnforced))
	redirectFlash(w, r, back, "Settings saved.")
}

func (s *Server) handleOrgDelete(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	if strings.TrimSpace(r.PostFormValue("confirm")) != oc.Org.Slug {
		redirectFlash(w, r, orgPath(oc, "settings"), "Type the organisation's slug exactly to confirm deletion.")
		return
	}
	// Audit rows have no foreign key, so this one outlives the org.
	s.audit(r, oc.Org.ID, "org.delete", oc.Org.Slug, "")
	if err := s.Keys.RevokeOrgKeys(oc.Org.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.IDs.DeleteOrg(r.Context(), oc.Org.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirectFlash(w, r, "/console", "Deleted "+oc.Org.Name+".")
}
