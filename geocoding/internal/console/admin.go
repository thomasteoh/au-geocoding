package console

import (
	"database/sql"
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
	id := pathInt(r, "id")
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
	// The org and its existing keys change tier in one transaction; the
	// in-memory key index follows once it commits.
	qt := publicapi.QuotaTier(tier)
	err = s.IDs.SetOrgTierWith(r.Context(), org.ID, tier, func(tx *sql.Tx) error {
		return s.Keys.SetOrgTierTx(r.Context(), tx, org.ID, qt)
	})
	if err != nil {
		if errors.Is(err, identity.ErrInvalid) {
			redirectFlash(w, r, "/console/admin/orgs", "Choose one of the listed tiers.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.Keys.ApplyOrgTier(org.ID, qt)
	s.audit(r, 0, "org.tier", org.Slug, "from="+org.Tier+" to="+tier)
	redirectFlash(w, r, "/console/admin/orgs", org.Name+" is now on the "+tier+" tier.")
}

// adminUsersPage is how many users the admin users page lists at once.
const adminUsersPage = 100

type adminUsersData struct {
	Query  string
	Users  []identity.User
	SelfID int64
	// Older and Newer are the before= and after= cursors of the neighbouring
	// pages, 0 when there is none. Before and After echo this page's cursor
	// so actions return to it.
	Older, Newer  int64
	Before, After int64
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	q := strings.TrimSpace(qs.Get("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	before, _ := strconv.ParseInt(qs.Get("before"), 10, 64)
	after, _ := strconv.ParseInt(qs.Get("after"), 10, 64)
	if before < 0 {
		before = 0
	}
	if after < 0 || before > 0 {
		after = 0
	}
	// One extra row says whether another page exists in the paging direction.
	users, err := s.IDs.ListUsers(r.Context(), q, before, after, adminUsersPage+1)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := adminUsersData{Query: q, SelfID: viewerFrom(r.Context()).User.ID, Before: before, After: after}
	more := len(users) > adminUsersPage
	var hasOlder, hasNewer bool
	if after > 0 {
		if more {
			users = users[1:] // the newest row belongs to the page above
		}
		hasOlder, hasNewer = true, more
	} else {
		if more {
			users = users[:adminUsersPage]
		}
		hasOlder, hasNewer = more, before > 0
	}
	d.Users = users
	if len(users) > 0 {
		if hasOlder {
			d.Older = users[len(users)-1].ID
		}
		if hasNewer {
			d.Newer = users[0].ID
		}
	}
	s.render(w, r, http.StatusOK, "admin_users", Page{Title: "Users", Active: "admin", Data: d})
}

// adminTargetUser loads the user named in the path; the viewer cannot act
// on themselves.
func (s *Server) adminTargetUser(w http.ResponseWriter, r *http.Request) (identity.User, string, bool) {
	back := adminUsersBack(r)
	id := pathInt(r, "id")
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

// adminUsersBack returns the users page an action was posted from: its
// search and page cursor.
func adminUsersBack(r *http.Request) string {
	v := url.Values{}
	if q := r.PostFormValue("q"); q != "" {
		v.Set("q", q)
	}
	for _, k := range []string{"before", "after"} {
		if n, err := strconv.ParseInt(r.PostFormValue(k), 10, 64); err == nil && n > 0 {
			v.Set(k, strconv.FormatInt(n, 10))
		}
	}
	if len(v) == 0 {
		return "/console/admin/users"
	}
	return "/console/admin/users?" + v.Encode()
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
	// Suspension deletes the user's sessions in the same transaction, and
	// refuses (atomically) to suspend the last active platform admin.
	if err := s.IDs.SetUserStatusGuarded(r.Context(), u.ID, status); err != nil {
		if errors.Is(err, identity.ErrLastPlatformAdmin) {
			redirectFlash(w, r, back, "You cannot suspend the last active platform admin.")
			return
		}
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
	var err error
	if grant {
		err = s.IDs.SetPlatformAdmin(r.Context(), u.ID, true)
	} else {
		// Refuses, atomically, to remove the last active platform admin.
		err = s.IDs.RevokePlatformAdmin(r.Context(), u.ID)
	}
	if err != nil {
		if errors.Is(err, identity.ErrLastPlatformAdmin) {
			redirectFlash(w, r, back, "You cannot remove the last active platform admin.")
			return
		}
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
