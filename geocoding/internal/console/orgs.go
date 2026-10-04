package console

import (
	"net/http"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
)

// registerOrgRoutes mounts /console/orgs/{org}/... pages.
func (s *Server) registerOrgRoutes(mux *http.ServeMux) {
	mux.Handle("GET /console/orgs/{org}", s.orgRoute(identity.RoleViewer, s.handleOrgOverview))
}

type overviewData struct {
	UsageToday int64
	Quota      int64
	Members    int
	Keys       int
}

func (s *Server) handleOrgOverview(w http.ResponseWriter, r *http.Request) {
	oc := orgFrom(r.Context())
	used, err := s.Keys.UsageToday(publicapi.OrgUsageKey(oc.Org.ID))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	members, _ := s.IDs.Members(r.Context(), oc.Org.ID)
	keys, _ := s.Keys.OrgKeys(oc.Org.ID)
	live := 0
	for _, k := range keys {
		if k.Revoked == nil {
			live++
		}
	}
	s.render(w, r, http.StatusOK, "org_overview", Page{Title: oc.Org.Name, Active: "overview", Data: overviewData{
		UsageToday: used, Quota: publicapi.TierQuota[publicapi.QuotaTier(oc.Org.Tier)], Members: len(members), Keys: live}})
}
