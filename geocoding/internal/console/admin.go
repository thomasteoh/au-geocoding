package console

import "net/http"

// registerAdminRoutes mounts /console/admin/... (platform admins only).
func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	mux.Handle("GET /console/admin", s.adminRoute(s.handleAdminHome))
}

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "error", Page{Title: "Platform admin", Active: "admin", Error: "Platform admin pages are not built yet."})
}
