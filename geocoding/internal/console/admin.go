package console

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
)

// registerAdminRoutes mounts /console/admin/... (platform admins only;
// everyone else gets 404). Platform actions are audited with org 0.
func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	p := func(h func(http.ResponseWriter, *http.Request, connScope)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { h(w, r, platformScope(r)) }
	}
	mux.Handle("GET /console/admin", s.adminRoute(s.handleAdminHome))
	mux.Handle("GET /console/admin/{$}", s.adminRoute(s.handleAdminHome))

	mux.Handle("GET /console/admin/orgs", s.adminRoute(s.handleAdminOrgs))
	mux.Handle("POST /console/admin/orgs/{id}/tier", s.adminPost(s.handleAdminOrgTier))

	mux.Handle("GET /console/admin/connections", s.adminRoute(p(s.handleConnList)))
	mux.Handle("GET /console/admin/connections/new", s.adminRoute(p(s.handleConnNew)))
	mux.Handle("POST /console/admin/connections", s.adminPost(p(s.handleConnCreate)))
	mux.Handle("GET /console/admin/connections/{id}", s.adminRoute(p(s.handleConnEdit)))
	mux.Handle("POST /console/admin/connections/{id}", s.adminPost(p(s.handleConnUpdate)))
	mux.Handle("POST /console/admin/connections/{id}/delete", s.adminPost(p(s.handleConnDelete)))

	mux.Handle("GET /console/admin/users", s.adminRoute(s.handleAdminUsers))
	mux.Handle("POST /console/admin/users/{id}/status", s.adminPost(s.handleAdminUserStatus))
	mux.Handle("POST /console/admin/users/{id}/admin", s.adminPost(s.handleAdminUserAdmin))
}

type adminHomeData struct {
	Orgs, Connections, Admins int
}

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	var d adminHomeData
	orgs, err := s.IDs.ListOrgs(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	conns, err := s.IDs.Connections(r.Context(), 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Orgs, d.Connections = len(orgs), len(conns)
	d.Admins, _ = s.IDs.CountPlatformAdmins(r.Context())
	s.render(w, r, http.StatusOK, "admin_home", Page{Title: "Platform admin", Active: "admin", Data: d})
}

type adminOrgRow struct {
	identity.Org
	Members int
}

type adminOrgsData struct {
	Orgs  []adminOrgRow
	Tiers []string
}

func (s *Server) handleAdminOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.IDs.ListOrgs(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := adminOrgsData{Tiers: identity.ValidTiers}
	for _, o := range orgs {
		ms, err := s.IDs.Members(r.Context(), o.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d.Orgs = append(d.Orgs, adminOrgRow{Org: o, Members: len(ms)})
	}
	s.render(w, r, http.StatusOK, "admin_orgs", Page{Title: "Organisations", Active: "admin", Data: d})
}

func (s *Server) handleAdminOrgTier(w http.ResponseWriter, r *http.Request) {
	id := pathID(r, "id")
	org, err := s.IDs.OrgByID(r.Context(), id)
	if id == 0 || errors.Is(err, identity.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tier := r.PostFormValue("tier")
	if err := s.IDs.SetOrgTier(r.Context(), org.ID, tier); err != nil {
		if errors.Is(err, identity.ErrInvalid) {
			redirectFlash(w, r, "/console/admin/orgs", "Choose one of the listed tiers.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	// Existing keys carry the tier too; update them and the in-memory index.
	if err := s.Keys.SetOrgTier(org.ID, publicapi.QuotaTier(tier)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, 0, "org.tier", org.Slug, "from="+org.Tier+" to="+tier)
	redirectFlash(w, r, "/console/admin/orgs", org.Name+" is now on the "+tier+" tier.")
}

type adminUsersData struct {
	Query  string
	Users  []identity.User
	SelfID int64
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	users, err := s.IDs.ListUsers(r.Context(), q, 200)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "admin_users", Page{Title: "Users", Active: "admin",
		Data: adminUsersData{Query: q, Users: users, SelfID: viewerFrom(r.Context()).User.ID}})
}

// adminTargetUser loads the user named in the path; the viewer cannot act
// on themselves.
func (s *Server) adminTargetUser(w http.ResponseWriter, r *http.Request) (identity.User, string, bool) {
	back := "/console/admin/users"
	if q := r.PostFormValue("q"); q != "" {
		back += "?q=" + url.QueryEscape(q)
	}
	id := pathID(r, "id")
	u, err := s.IDs.UserByID(r.Context(), id)
	if id == 0 || errors.Is(err, identity.ErrNotFound) {
		s.notFound(w, r)
		return u, back, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return u, back, false
	}
	if u.ID == viewerFrom(r.Context()).User.ID {
		redirectFlash(w, r, back, "You cannot change your own account here.")
		return u, back, false
	}
	return u, back, true
}

// lastAdmin reports whether u is the only active platform admin.
func (s *Server) lastAdmin(r *http.Request, u identity.User) (bool, error) {
	if !u.PlatformAdmin || !u.Active() {
		return false, nil
	}
	n, err := s.IDs.CountPlatformAdmins(r.Context())
	return n <= 1, err
}

func (s *Server) handleAdminUserStatus(w http.ResponseWriter, r *http.Request) {
	u, back, ok := s.adminTargetUser(w, r)
	if !ok {
		return
	}
	status := r.PostFormValue("status")
	if status != identity.StatusActive && status != identity.StatusSuspended {
		redirectFlash(w, r, back, "Unknown status.")
		return
	}
	if status == identity.StatusSuspended {
		last, err := s.lastAdmin(r, u)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if last {
			redirectFlash(w, r, back, "You cannot suspend the last active platform admin.")
			return
		}
	}
	// Suspension deletes the user's sessions in the same transaction.
	if err := s.IDs.SetUserStatus(r.Context(), u.ID, status); err != nil {
		s.serverError(w, r, err)
		return
	}
	action := "user.suspend"
	msg := "Suspended " + u.Email + " and ended their sessions."
	if status == identity.StatusActive {
		action, msg = "user.reactivate", "Reactivated "+u.Email+"."
	}
	s.audit(r, 0, action, u.Email, "user_id="+strconv.FormatInt(u.ID, 10))
	redirectFlash(w, r, back, msg)
}

func (s *Server) handleAdminUserAdmin(w http.ResponseWriter, r *http.Request) {
	u, back, ok := s.adminTargetUser(w, r)
	if !ok {
		return
	}
	grant := r.PostFormValue("admin") == "1"
	if !grant {
		last, err := s.lastAdmin(r, u)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if last {
			redirectFlash(w, r, back, "You cannot remove the last active platform admin.")
			return
		}
	}
	if err := s.IDs.SetPlatformAdmin(r.Context(), u.ID, grant); err != nil {
		s.serverError(w, r, err)
		return
	}
	action, msg := "platform_admin.grant", u.Email+" is now a platform admin."
	if !grant {
		action, msg = "platform_admin.revoke", u.Email+" is no longer a platform admin."
	}
	s.audit(r, 0, action, u.Email, "user_id="+strconv.FormatInt(u.ID, 10))
	redirectFlash(w, r, back, msg)
}
