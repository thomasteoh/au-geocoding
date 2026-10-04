// Package apiauth turns a public API request into a publicapi.Principal: an
// API key (X-Api-Key), an OAuth2/OIDC access token (Authorization: Bearer)
// from an org-registered issuer, or the anonymous tier (docs/auth.md "API").
//
// Every credential failure is ErrInvalidKey so the API answers with one
// uniform 401 (T6). The reason goes to the log as a code, never the token.
package apiauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"augeocoding/internal/identity"
	"augeocoding/internal/publicapi"
	"augeocoding/internal/safehttp"
)

// ErrBothCredentials is returned when a request carries an API key and a
// bearer token; the caller must pick one (400).
var ErrBothCredentials = errors.New("supply either X-Api-Key or Authorization, not both")

// IssuerSource looks up registered JWT issuers and their orgs.
type IssuerSource interface {
	EnabledJWTIssuers(ctx context.Context, iss string) ([]identity.JWTIssuer, error)
	OrgByID(ctx context.Context, id int64) (identity.Org, error)
}

// Authenticator resolves request credentials.
type Authenticator struct {
	Keys        *publicapi.Store
	Issuers     IssuerSource // nil disables bearer tokens
	KeyLimiter  *publicapi.RateLimiter
	AnonLimiter *publicapi.RateLimiter
	ClientIP    func(*http.Request) string
	// Reject is called with a reason code when a credential is refused.
	Reject func(reason string)
	// HTTPClient fetches discovery documents and JWKS. Issuer URLs are
	// org-controlled, so production uses safehttp.Client (no private
	// addresses); nil means exactly that.
	HTTPClient *http.Client

	mu   sync.Mutex
	sets map[string]*keySet // by issuer row ID + JWKS URL
}

type keySet struct {
	set     *oidc.RemoteKeySet
	fetched time.Time
}

// Leeway is the allowed clock skew for exp/nbf/iat.
const Leeway = 60 * time.Second

// keySetTTL bounds how long a discovered JWKS URL is reused before discovery
// runs again (keys themselves refresh on unknown kid).
const keySetTTL = time.Hour

func (a *Authenticator) reject(reason string) error {
	if a.Reject != nil {
		a.Reject(reason)
	}
	return publicapi.ErrInvalidKey
}

// Authenticate resolves the request's principal and applies its rate limit.
// Errors: publicapi.ErrInvalidKey (401), publicapi.ErrRateLimited (429),
// ErrBothCredentials (400).
func (a *Authenticator) Authenticate(r *http.Request) (publicapi.Principal, error) {
	keyStr := r.Header.Get("X-Api-Key")
	authz := r.Header.Get("Authorization")
	switch {
	case keyStr != "" && authz != "":
		return publicapi.Principal{}, ErrBothCredentials
	case keyStr != "":
		k, err := a.Keys.Authenticate(keyStr)
		if err != nil {
			// Uniform 401 for unknown/revoked/disabled/expired (T6) — never
			// fall through to anonymous.
			return publicapi.Principal{}, a.reject("invalid_key")
		}
		p := publicapi.KeyPrincipal(k)
		if !a.KeyLimiter.Allow(p.RateKey) {
			return p, publicapi.ErrRateLimited
		}
		return p, nil
	case authz != "":
		p, err := a.bearer(r.Context(), authz)
		if err != nil {
			return publicapi.Principal{}, err
		}
		if !a.KeyLimiter.Allow(p.RateKey) {
			return p, publicapi.ErrRateLimited
		}
		return p, nil
	}
	// Anonymous is limited per IP, not per connection.
	ip := a.ClientIP(r)
	p := publicapi.Principal{Kind: "anonymous", Tier: publicapi.TierAnonymous, RateKey: "anon:" + ip}
	if !a.AnonLimiter.Allow(p.RateKey) {
		return p, publicapi.ErrRateLimited
	}
	return p, nil
}

// signatureAlgs is the asymmetric allowlist (auth.md A8): never "none", never
// HMAC, whose "key" would be whatever the attacker says the public key is.
var signatureAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

type claims struct {
	Issuer    string           `json:"iss"`
	Subject   string           `json:"sub"`
	Audience  jwt.Audience     `json:"aud"`
	Expiry    *jwt.NumericDate `json:"exp"`
	NotBefore *jwt.NumericDate `json:"nbf"`
	IssuedAt  *jwt.NumericDate `json:"iat"`
	Scope     string           `json:"scope"`
	Scp       json.RawMessage  `json:"scp"`
	Roles     []string         `json:"roles"`
	ClientID  string           `json:"client_id"`
	AZP       string           `json:"azp"`
}

func (a *Authenticator) bearer(ctx context.Context, authz string) (publicapi.Principal, error) {
	if a.Issuers == nil {
		return publicapi.Principal{}, a.reject("bearer_disabled")
	}
	scheme, raw, ok := strings.Cut(authz, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return publicapi.Principal{}, a.reject("bad_authorization")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 16<<10 {
		return publicapi.Principal{}, a.reject("bad_token")
	}
	tok, err := jwt.ParseSigned(raw, signatureAlgs)
	if err != nil {
		return publicapi.Principal{}, a.reject("bad_token")
	}
	// The issuer is read before verification only to choose which key set
	// verifies the signature; nothing else is trusted until it passes.
	var unverified claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer == "" {
		return publicapi.Principal{}, a.reject("bad_token")
	}
	regs, err := a.Issuers.EnabledJWTIssuers(ctx, unverified.Issuer)
	if err != nil || len(regs) == 0 {
		return publicapi.Principal{}, a.reject("unknown_issuer")
	}
	// Choose the registration by the (still unverified) audience, then
	// verify with that registration's own keys. Verifying with any other
	// registration's keys would let one org's JWKS vouch for a token aimed at
	// another org's audience.
	var iss identity.JWTIssuer
	matches := 0
	for _, r := range regs {
		if unverified.Audience.Contains(r.Audience) {
			iss = r
			matches++
		}
	}
	if matches != 1 {
		return publicapi.Principal{}, a.reject("audience")
	}
	ks, err := a.keySet(ctx, iss)
	if err != nil {
		return publicapi.Principal{}, a.reject("jwks_unavailable")
	}
	payload, err := ks.VerifySignature(ctx, raw)
	if err != nil {
		return publicapi.Principal{}, a.reject("bad_signature")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return publicapi.Principal{}, a.reject("bad_claims")
	}
	if c.Issuer != iss.Issuer || !c.Audience.Contains(iss.Audience) {
		return publicapi.Principal{}, a.reject("issuer_mismatch")
	}
	now := time.Now()
	if c.Expiry == nil || now.After(c.Expiry.Time().Add(Leeway)) {
		return publicapi.Principal{}, a.reject("expired")
	}
	if c.NotBefore != nil && now.Add(Leeway).Before(c.NotBefore.Time()) {
		return publicapi.Principal{}, a.reject("not_yet_valid")
	}
	if c.IssuedAt != nil && now.Add(Leeway).Before(c.IssuedAt.Time()) {
		return publicapi.Principal{}, a.reject("issued_in_future")
	}
	sub := c.Subject
	if sub == "" {
		sub = firstNonEmpty(c.ClientID, c.AZP)
	}
	if sub == "" {
		return publicapi.Principal{}, a.reject("no_subject")
	}
	if len(iss.AllowedSubjects) > 0 && !contains(iss.AllowedSubjects, sub) && !contains(iss.AllowedSubjects, c.ClientID) && !contains(iss.AllowedSubjects, c.AZP) {
		return publicapi.Principal{}, a.reject("subject_not_allowed")
	}
	org, err := a.Issuers.OrgByID(ctx, iss.OrgID)
	if err != nil {
		return publicapi.Principal{}, a.reject("issuer_org")
	}
	scopes := MapScopes(c.Scope, c.Scp, c.Roles, iss.ScopePrefix)
	if len(scopes) == 0 {
		return publicapi.Principal{}, a.reject("no_scope")
	}
	subject := "jwt:" + strconv.FormatInt(iss.ID, 10) + ":" + sub
	return publicapi.Principal{
		Kind:     "jwt",
		OrgID:    org.ID,
		Tier:     publicapi.QuotaTier(org.Tier),
		Scopes:   scopes,
		RateKey:  subject,
		UsageKey: publicapi.OrgUsageKey(org.ID),
		Subject:  subject,
	}, nil
}

// knownScopes are the API scopes a token can grant.
var knownScopes = map[string]bool{"search": true, "batch": true}

// MapScopes collects scopes from the token's scope (space-separated), scp
// (array, or space-separated string as Entra sends it) and roles (Entra app
// roles for client credentials), keeps those with the issuer's prefix, strips
// the prefix, and returns the known API scopes. A token with no API scope
// gets nothing: unlike keys, a bearer token never defaults to "search".
func MapScopes(scope string, scp json.RawMessage, roles []string, prefix string) []string {
	var all []string
	all = append(all, strings.Fields(scope)...)
	if len(scp) > 0 {
		var arr []string
		var str string
		if json.Unmarshal(scp, &arr) == nil {
			all = append(all, arr...)
		} else if json.Unmarshal(scp, &str) == nil {
			all = append(all, strings.Fields(str)...)
		}
	}
	all = append(all, roles...)
	seen := map[string]bool{}
	var out []string
	for _, s := range all {
		if prefix != "" {
			if !strings.HasPrefix(s, prefix) {
				continue
			}
			s = s[len(prefix):]
		}
		s = strings.ToLower(s)
		if knownScopes[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (a *Authenticator) client() *http.Client {
	if a.HTTPClient != nil {
		return a.HTTPClient
	}
	return safehttp.Client(10*time.Second, false)
}

// keySet returns the cached key set for an issuer row, running discovery
// when no JWKS URL is configured.
func (a *Authenticator) keySet(ctx context.Context, iss identity.JWTIssuer) (*oidc.RemoteKeySet, error) {
	cacheKey := strconv.FormatInt(iss.ID, 10) + "|" + iss.Issuer + "|" + iss.JWKSURL
	a.mu.Lock()
	if a.sets == nil {
		a.sets = map[string]*keySet{}
	}
	if ks, ok := a.sets[cacheKey]; ok && time.Since(ks.fetched) < keySetTTL {
		a.mu.Unlock()
		return ks.set, nil
	}
	a.mu.Unlock()

	jwksURL := iss.JWKSURL
	if jwksURL == "" {
		var err error
		if jwksURL, err = a.discoverJWKS(ctx, iss.Issuer); err != nil {
			return nil, err
		}
	}
	set := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), a.client()), jwksURL)
	a.mu.Lock()
	a.sets[cacheKey] = &keySet{set: set, fetched: time.Now()}
	a.mu.Unlock()
	return set, nil
}

// discoverJWKS reads jwks_uri from OIDC discovery, falling back to RFC 8414
// authorization server metadata. The document's issuer must match.
func (a *Authenticator) discoverJWKS(ctx context.Context, issuer string) (string, error) {
	base := strings.TrimSuffix(issuer, "/")
	for _, u := range []string{base + "/.well-known/openid-configuration", base + "/.well-known/oauth-authorization-server"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		resp, err := a.client().Do(req)
		if err != nil {
			continue
		}
		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		if doc.Issuer != issuer || doc.JWKSURI == "" {
			return "", fmt.Errorf("discovery: issuer mismatch or no jwks_uri")
		}
		return doc.JWKSURI, nil
	}
	return "", fmt.Errorf("discovery failed for %s", issuer)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	if s == "" {
		return false
	}
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
