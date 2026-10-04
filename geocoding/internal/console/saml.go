package console

import "net/http"

// SAML 2.0 service provider routes (docs/auth.md "SAML 2.0").

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleSAMLStart(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotImplemented, "SAML sign-in is not available yet.")
}

func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotImplemented, "SAML sign-in is not available yet.")
}
