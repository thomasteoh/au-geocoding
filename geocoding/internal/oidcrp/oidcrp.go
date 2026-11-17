// Package oidcrp is the OpenID Connect (and GitHub OAuth2) relying party for
// console sign-in: authorization code flow with PKCE, state and nonce, RFC
// 9207 issuer checks, ID token verification, RP-initiated logout and
// back-channel logout (docs/auth.md).
package oidcrp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"augeocoding/internal/identity"
)

// Errors surfaced to the console as a generic sign-in failure; the code goes
// to the audit log.
var (
	ErrIssuerMismatch = errors.New("oidc: issuer in authorization response does not match")
	ErrIdP            = errors.New("oidc: identity provider returned an error")
	ErrToken          = errors.New("oidc: token exchange or verification failed")
)

// RP is the relying party. One instance serves every connection.
type RP struct {
	// CallbackURL is the single redirect URI registered at every IdP
	// ({public}/auth/oidc/callback). One callback for all connections means
	// the connection comes from the flow (state), never from the URL (A3).
	CallbackURL string
	// HTTP is used for discovery, JWKS, token and userinfo calls. Issuers are
	// admin-controlled, so production passes safehttp.Client.
	HTTP *http.Client
	// GitHub endpoints; zero value means github.com.
	GitHub GitHubEndpoints
	// GraphURL is Microsoft Graph, for Entra group overage; "" means
	// https://graph.microsoft.com/v1.0.
	GraphURL string

	mu        sync.Mutex
	providers map[string]cachedProvider
}

type cachedProvider struct {
	p       *oidc.Provider
	fetched time.Time
}

const providerTTL = time.Hour

func (rp *RP) ctx(ctx context.Context) context.Context {
	if rp.HTTP != nil {
		return oidc.ClientContext(ctx, rp.HTTP)
	}
	return ctx
}

// provider returns the discovered provider for a connection, cached for an
// hour. Multi-tenant Entra issuers are discovered with the issuer check off;
// tokens are checked per tenant in verifyMultiTenant instead.
func (rp *RP) provider(ctx context.Context, c identity.Connection) (*oidc.Provider, error) {
	key := c.Issuer
	rp.mu.Lock()
	if rp.providers == nil {
		rp.providers = map[string]cachedProvider{}
	}
	if cp, ok := rp.providers[key]; ok && time.Since(cp.fetched) < providerTTL {
		rp.mu.Unlock()
		return cp.p, nil
	}
	rp.mu.Unlock()
	dctx := rp.ctx(ctx)
	if pr := PresetFor(c.Preset); pr.MultiTenant != nil && pr.MultiTenant(c.Issuer) {
		dctx = oidc.InsecureIssuerURLContext(dctx, c.Issuer)
	}
	p, err := oidc.NewProvider(dctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", c.Slug, err)
	}
	rp.mu.Lock()
	rp.providers[key] = cachedProvider{p: p, fetched: time.Now()}
	rp.mu.Unlock()
	return p, nil
}

// Forget drops a cached provider (after a connection is edited).
func (rp *RP) Forget(issuer string) {
	rp.mu.Lock()
	delete(rp.providers, issuer)
	rp.mu.Unlock()
}

func scopesFor(c identity.Connection) []string {
	if len(c.Scopes) > 0 {
		s := c.Scopes
		if !contains(s, oidc.ScopeOpenID) && c.Kind == identity.KindOIDC {
			s = append([]string{oidc.ScopeOpenID}, s...)
		}
		return s
	}
	if c.Kind == identity.KindGitHub {
		return githubScopes(c)
	}
	return PresetFor(c.Preset).Scopes
}

func (rp *RP) oauthConfig(c identity.Connection, ep oauth2.Endpoint) *oauth2.Config {
	return &oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: ep, RedirectURL: rp.CallbackURL, Scopes: scopesFor(c)}
}

// AuthURL builds the authorization request. state, nonce and the PKCE
// verifier come from the stored flow.
func (rp *RP) AuthURL(ctx context.Context, c identity.Connection, state, nonce, verifier string) (string, error) {
	if c.Kind == identity.KindGitHub {
		return rp.oauthConfig(c, rp.GitHub.endpoint(c)).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
	}
	p, err := rp.provider(ctx, c)
	if err != nil {
		return "", err
	}
	return rp.oauthConfig(c, p.Endpoint()).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Claims are the ID token claims the console uses.
type Claims struct {
	Subject       string         `json:"sub"`
	Email         string         `json:"email"`
	EmailVerified flexBool       `json:"email_verified"`
	Name          string         `json:"name"`
	PreferredName string         `json:"preferred_username"`
	SID           string         `json:"sid"`
	TenantID      string         `json:"tid"`
	XMSEdov       flexBool       `json:"xms_edov"`
	Raw           map[string]any `json:"-"`
}

// Callback completes an OIDC or GitHub login from the redirect's query
// parameters and returns a verified assertion. flow is the consumed flow.
func (rp *RP) Callback(ctx context.Context, c identity.Connection, f identity.Flow, q url.Values) (identity.Assertion, error) {
	if e := q.Get("error"); e != "" {
		return identity.Assertion{}, fmt.Errorf("%w: %s", ErrIdP, truncate(e, 64))
	}
	code := q.Get("code")
	if code == "" {
		return identity.Assertion{}, ErrToken
	}
	if c.Kind == identity.KindGitHub {
		return rp.githubCallback(ctx, c, f, code)
	}
	p, err := rp.provider(ctx, c)
	if err != nil {
		return identity.Assertion{}, err
	}
	multi := PresetFor(c.Preset).MultiTenant != nil && PresetFor(c.Preset).MultiTenant(c.Issuer)
	// RFC 9207: when the IdP says who it is, it must be who we asked (A3).
	if iss := q.Get("iss"); iss != "" && iss != c.Issuer && !multi {
		return identity.Assertion{}, ErrIssuerMismatch
	}
	cfg := rp.oauthConfig(c, p.Endpoint())
	tok, err := cfg.Exchange(rp.ctx(ctx), code, oauth2.VerifierOption(f.PKCEVerifier))
	if err != nil {
		return identity.Assertion{}, fmt.Errorf("%w: exchange: %v", ErrToken, err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return identity.Assertion{}, fmt.Errorf("%w: no id_token", ErrToken)
	}
	v := p.VerifierContext(rp.ctx(ctx), &oidc.Config{ClientID: c.ClientID, SkipIssuerCheck: multi})
	idt, err := v.Verify(rp.ctx(ctx), rawID)
	if err != nil {
		return identity.Assertion{}, fmt.Errorf("%w: id_token: %v", ErrToken, err)
	}
	if idt.Nonce == "" || idt.Nonce != f.Nonce {
		return identity.Assertion{}, fmt.Errorf("%w: nonce", ErrToken)
	}
	var cl Claims
	if err := idt.Claims(&cl); err != nil {
		return identity.Assertion{}, fmt.Errorf("%w: claims: %v", ErrToken, err)
	}
	if err := idt.Claims(&cl.Raw); err != nil {
		return identity.Assertion{}, fmt.Errorf("%w: claims: %v", ErrToken, err)
	}
	if len(c.AllowedTenants) > 0 && !contains(c.AllowedTenants, strings.ToLower(cl.TenantID)) {
		// The connection is pinned to specific Entra tenants.
		return identity.Assertion{}, &identity.Denial{Code: "tenant_not_allowed", Message: "Your Microsoft organisation is not allowed to use this sign-in."}
	}
	if multi {
		// Per-tenant issuer: iss must be the tenant's own v2.0 issuer.
		if cl.TenantID == "" || idt.Issuer != "https://login.microsoftonline.com/"+cl.TenantID+"/v2.0" {
			return identity.Assertion{}, fmt.Errorf("%w: tenant issuer", ErrToken)
		}
		if iss := q.Get("iss"); iss != "" && iss != idt.Issuer {
			return identity.Assertion{}, ErrIssuerMismatch
		}
	}
	pr := PresetFor(c.Preset)
	email := cl.Email
	if email == "" && strings.Contains(cl.PreferredName, "@") && c.Preset != "entra" {
		email = cl.PreferredName
	}
	name := cl.Name
	if name == "" {
		name = cl.PreferredName
	}
	groupsClaim := c.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = pr.GroupsClaim
	}
	groups := stringList(cl.Raw[groupsClaim])
	groupsUnknown := false
	if c.Preset == "entra" && entraOverage(cl.Raw) {
		// Entra leaves groups out of the token when there are too many (or
		// for implicit flows) and says so. Ask Graph; if that fails, the
		// role is left alone rather than recomputed from nothing.
		if g, err := rp.entraGroups(ctx, tok.AccessToken); err == nil {
			groups = g
		} else {
			groupsUnknown = true
		}
	}
	subject := cl.Subject
	if multi {
		// Entra subjects are pairwise per app but not globally unique across
		// tenants; qualify with the tenant.
		subject = cl.TenantID + ":" + cl.Subject
	}
	return identity.Assertion{
		Connection: c,
		Subject:    subject,
		Email:      email,
		// Only a real email claim is ever trusted, never the user-chosen
		// preferred_username fallback.
		EmailTrusted:  cl.Email != "" && ((pr.TrustEmail != nil && pr.TrustEmail(cl)) || c.TrustEmail),
		Name:          truncate(name, 100),
		Groups:        groups,
		GroupsUnknown: groupsUnknown,
		IdPSID:        cl.SID,
		IDToken:       rawID,
	}, nil
}

// EndSessionURL returns the IdP's RP-initiated logout URL, if it has one.
func (rp *RP) EndSessionURL(ctx context.Context, c identity.Connection, idToken, postLogout string) (string, bool) {
	if c.Kind != identity.KindOIDC {
		return "", false
	}
	p, err := rp.provider(ctx, c)
	if err != nil {
		return "", false
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&meta); err != nil || meta.EndSession == "" {
		return "", false
	}
	u, err := url.Parse(meta.EndSession)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", false
	}
	q := u.Query()
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	q.Set("client_id", c.ClientID)
	q.Set("post_logout_redirect_uri", postLogout)
	u.RawQuery = q.Encode()
	return u.String(), true
}

// LogoutToken is a verified back-channel logout request.
type LogoutToken struct {
	SID     string
	Subject string
	JTI     string
	Expires time.Time
}

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// VerifyLogoutToken checks an OIDC back-channel logout token (A6): signature
// against the connection's keys, iss, aud, iat freshness, the back-channel
// event, no nonce, a jti, and a sid or sub. Replay is the caller's job (jti).
func (rp *RP) VerifyLogoutToken(ctx context.Context, c identity.Connection, raw string) (LogoutToken, error) {
	if c.Kind != identity.KindOIDC || raw == "" || len(raw) > 16<<10 {
		return LogoutToken{}, ErrToken
	}
	p, err := rp.provider(ctx, c)
	if err != nil {
		return LogoutToken{}, err
	}
	multi := PresetFor(c.Preset).MultiTenant != nil && PresetFor(c.Preset).MultiTenant(c.Issuer)
	v := p.VerifierContext(rp.ctx(ctx), &oidc.Config{ClientID: c.ClientID, SkipExpiryCheck: true, SkipIssuerCheck: multi})
	t, err := v.Verify(rp.ctx(ctx), raw)
	if err != nil {
		return LogoutToken{}, fmt.Errorf("%w: %v", ErrToken, err)
	}
	var cl struct {
		JTI    string                     `json:"jti"`
		Events map[string]json.RawMessage `json:"events"`
		Nonce  *string                    `json:"nonce"`
		SID    string                     `json:"sid"`
		Exp    *int64                     `json:"exp"`
		TID    string                     `json:"tid"`
	}
	if err := t.Claims(&cl); err != nil {
		return LogoutToken{}, ErrToken
	}
	now := time.Now()
	switch {
	case cl.Nonce != nil:
		return LogoutToken{}, fmt.Errorf("%w: nonce present", ErrToken)
	case cl.JTI == "":
		return LogoutToken{}, fmt.Errorf("%w: no jti", ErrToken)
	case cl.Events == nil || cl.Events[backchannelEvent] == nil:
		return LogoutToken{}, fmt.Errorf("%w: not a logout event", ErrToken)
	case cl.SID == "" && t.Subject == "":
		return LogoutToken{}, fmt.Errorf("%w: no sid or sub", ErrToken)
	case t.IssuedAt.IsZero() || now.Sub(t.IssuedAt) > 10*time.Minute || t.IssuedAt.Sub(now) > time.Minute:
		return LogoutToken{}, fmt.Errorf("%w: stale iat", ErrToken)
	case cl.Exp != nil && now.After(time.Unix(*cl.Exp, 0).Add(time.Minute)):
		return LogoutToken{}, fmt.Errorf("%w: expired", ErrToken)
	}
	if len(c.AllowedTenants) > 0 && !contains(c.AllowedTenants, strings.ToLower(cl.TID)) {
		return LogoutToken{}, fmt.Errorf("%w: tenant not allowed", ErrToken)
	}
	if multi && (cl.TID == "" || t.Issuer != "https://login.microsoftonline.com/"+cl.TID+"/v2.0") {
		return LogoutToken{}, fmt.Errorf("%w: tenant issuer", ErrToken)
	}
	sub := t.Subject
	if multi && sub != "" {
		sub = cl.TID + ":" + sub
	}
	exp := now.Add(time.Hour)
	if cl.Exp != nil {
		exp = time.Unix(*cl.Exp, 0).Add(time.Hour)
	}
	return LogoutToken{SID: cl.SID, Subject: sub, JTI: cl.JTI, Expires: exp}, nil
}

// flexBool accepts true, "true", 1.
type flexBool bool

func (b *flexBool) UnmarshalJSON(d []byte) error {
	s := strings.Trim(strings.ToLower(string(d)), `"`)
	*b = flexBool(s == "true" || s == "1")
	return nil
}

func (b flexBool) Bool() bool { return bool(b) }

// stringList reads a groups claim given as an array or a space/comma
// separated string.
func stringList(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" && len(out) < 1000 {
				out = append(out, truncate(s, 256))
			}
		}
		return out
	case string:
		// One string is one group (ADFS sends a lone group that way); only
		// commas separate. Splitting on spaces would turn "Finance Admins"
		// into a member of "Admins".
		var out []string
		for _, g := range strings.Split(x, ",") {
			if g = strings.TrimSpace(g); g != "" {
				out = append(out, truncate(g, 256))
			}
		}
		return out
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// entraOverage reports whether an Entra ID token signals that its groups
// claim was omitted (_claim_names.groups or hasgroups).
func entraOverage(raw map[string]any) bool {
	if names, ok := raw["_claim_names"].(map[string]any); ok {
		if _, ok := names["groups"]; ok {
			return true
		}
	}
	if b, ok := raw["hasgroups"].(bool); ok && b {
		return true
	}
	return false
}

// entraGroups fetches the signed-in user's group IDs from Microsoft Graph
// (getMemberGroups, which needs GroupMember.Read.All or Directory.Read.All
// consented for the app).
func (rp *RP) entraGroups(ctx context.Context, accessToken string) ([]string, error) {
	if accessToken == "" {
		return nil, errors.New("no access token")
	}
	base := rp.GraphURL
	if base == "" {
		base = "https://graph.microsoft.com/v1.0"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/me/getMemberGroups", strings.NewReader(`{"securityEnabledOnly":false}`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	client := rp.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graph getMemberGroups: status %d", resp.StatusCode)
	}
	var out struct {
		Value []string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Value) > 5000 {
		out.Value = out.Value[:5000]
	}
	return out.Value, nil
}
