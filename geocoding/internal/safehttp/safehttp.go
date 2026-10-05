// Package safehttp is the HTTP client for URLs that org admins control:
// OIDC discovery, JWKS and SAML metadata. Those URLs are fetched by the
// server, so without a guard an admin could point one at an internal service
// (SSRF). The client refuses to connect to loopback, private, link-local,
// CGNAT and other non-public addresses, after DNS resolution, on every dial
// (so a redirect or DNS rebinding cannot route around it).
package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlocked is returned when a dial targets a non-public address.
var ErrBlocked = errors.New("safehttp: destination address is not public")

// Client returns an HTTP client that only connects to public addresses. With
// allowPrivate (development and tests) every address is allowed.
func Client(timeout time.Duration, allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !allowPrivate {
		d.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return ErrBlocked
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !Public(ip) {
				return ErrBlocked
			}
			return nil
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // a proxy would dial on our behalf and bypass the check
	tr.DialContext = d.DialContext
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("safehttp: too many redirects")
			}
			if req.URL.Scheme != "https" && !allowPrivate {
				return errors.New("safehttp: redirect to non-https URL")
			}
			return nil
		},
	}
}

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 private space
	netip.MustParsePrefix("2001:db8::/32"),
}

// Public reports whether ip is a globally routable unicast address.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// ctxKey lets tests inject a client through a context; unused in production.
type ctxKey struct{}

// WithClient returns ctx carrying c.
func WithClient(ctx context.Context, c *http.Client) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext returns the client in ctx, or nil.
func FromContext(ctx context.Context) *http.Client {
	c, _ := ctx.Value(ctxKey{}).(*http.Client)
	return c
}
