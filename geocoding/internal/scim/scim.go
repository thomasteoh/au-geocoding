// Package scim is the SCIM 2.0 provisioning server (docs/auth.md "SCIM 2.0").
package scim

import (
	"net/http"

	"augeocoding/internal/identity"
	"ausystem/shared/slog"
)

// Server serves /scim/v2/.
type Server struct {
	IDs     *identity.Store
	Log     *slog.Logger
	BaseURL string // absolute, e.g. https://geo.example.com/scim/v2
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
