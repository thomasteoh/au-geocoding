package console

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"augeocoding/internal/authtest"
	"augeocoding/internal/publicapi"
)

func TestAuthRateLimit(t *testing.T) {
	h := newHarness(t, open)
	h.con.AuthLimiter = publicapi.NewRateLimiter(0.001, 3)
	var ip atomic.Value // read by server goroutines
	ip.Store("198.51.100.1")
	h.con.ClientIP = func(*http.Request) string { return ip.Load().(string) }
	b := h.browser()

	// Discover, OIDC start and the callback share one bucket per IP.
	for i := 0; i < 3; i++ {
		if r := b.post("/auth/discover", url.Values{"email": {"a@example.com"}}, false); r.Status == http.StatusTooManyRequests {
			t.Fatalf("request %d limited", i)
		}
	}
	for _, path := range []string{"/auth/discover", "/auth/oidc/test-idp/start", "/auth/oidc/callback?state=x", "/auth/saml/x/start"} {
		var r resp
		if strings.HasPrefix(path, "/auth/discover") {
			r = b.post(path, url.Values{"email": {"a@example.com"}}, false)
		} else {
			r = b.get(path)
		}
		if r.Status != http.StatusTooManyRequests || !strings.Contains(r.Body, "Too many sign-in attempts") {
			t.Fatalf("%s over the limit: %d", path, r.Status)
		}
	}
	// The passkey endpoints answer JSON.
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/auth/passkey/login/begin", strings.NewReader("{}"))
	req.Header.Set("Origin", h.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	res, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Retry-After") == "" {
		t.Fatalf("passkey begin: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}

	// Another client address has its own bucket, and signed-in console
	// pages are not limited.
	ip.Store("198.51.100.2")
	b2 := h.browser()
	b2.mustLogin(authtest.User{Subject: "s1", Email: "owner@acme.example", EmailVerified: true})
	ip.Store("198.51.100.1")
	if r := b2.get("/console/account"); r.Status != http.StatusOK {
		t.Fatalf("console page limited: %d", r.Status)
	}
}
