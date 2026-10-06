package console

import (
	"net"
	"net/http"
	"strings"
)

// clientIP is the address rate limits key on: Server.ClientIP (which knows
// about the trusted proxy) or the TCP peer.
func (s *Server) clientIP(r *http.Request) string {
	if s.ClientIP != nil {
		if ip := s.ClientIP(r); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authRateLimit applies AuthLimiter to an anonymous sign-in endpoint. Over
// the limit it answers 429: JSON for the passkey endpoints (called from
// script), an error page otherwise.
func (s *Server) authRateLimit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.AuthLimiter == nil || s.AuthLimiter.Allow("auth:"+s.clientIP(r)) {
			h.ServeHTTP(w, r)
			return
		}
		s.Log.Debug("auth_rate_limited", "path", r.URL.Path)
		w.Header().Set("Retry-After", "5")
		const msg = "Too many sign-in attempts from your network. Wait a few seconds and try again."
		if strings.HasPrefix(r.URL.Path, "/auth/passkey/") {
			jsonError(w, http.StatusTooManyRequests, msg)
			return
		}
		s.renderError(w, r, http.StatusTooManyRequests, msg)
	})
}
