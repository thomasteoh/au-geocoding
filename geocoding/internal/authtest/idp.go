// Package authtest provides an in-process OpenID Provider for tests: OIDC
// discovery, JWKS, an auto-approving authorization endpoint with PKCE, a
// token endpoint, and a signer for arbitrary JWTs (API access tokens,
// back-channel logout tokens).
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is who the IdP signs in at the next authorization request.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
	SID           string
}

// IdP is a fake OpenID Provider.
type IdP struct {
	Server       *httptest.Server
	Issuer       string
	ClientID     string
	ClientSecret string
	Key          *rsa.PrivateKey
	KeyID        string

	mu    sync.Mutex
	next  User
	codes map[string]codeGrant
	// OmitIssParam drops the RFC 9207 iss parameter from redirects.
	OmitIssParam bool
	// IssParamOverride sets a wrong iss on redirects (mix-up tests).
	IssParamOverride string
	// Tamper, if set, edits ID token claims before signing.
	Tamper func(map[string]any)
}

type codeGrant struct {
	user        User
	nonce       string
	challenge   string
	redirectURI string
}

// NewIdP starts a provider and registers cleanup with t.
func NewIdP(t testing.TB) *IdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{ClientID: "test-client", ClientSecret: "test-secret", Key: key, KeyID: "k1", codes: map[string]codeGrant{}}
	mux := http.NewServeMux()
	p.Server = httptest.NewServer(mux)
	p.Issuer = p.Server.URL
	t.Cleanup(p.Server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                p.Issuer,
			"authorization_endpoint":                p.Issuer + "/authorize",
			"token_endpoint":                        p.Issuer + "/token",
			"jwks_uri":                              p.Issuer + "/jwks",
			"userinfo_endpoint":                     p.Issuer + "/userinfo",
			"end_session_endpoint":                  p.Issuer + "/logout",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
			"backchannel_logout_supported":          true,
			"backchannel_logout_session_supported":  true,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.Key.PublicKey, KeyID: p.KeyID, Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	return p
}

// SetUser sets who the next authorization signs in.
func (p *IdP) SetUser(u User) {
	p.mu.Lock()
	p.next = u
	p.mu.Unlock()
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" {
		http.Error(w, "bad client or response_type", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "pkce required", http.StatusBadRequest)
		return
	}
	code := randString()
	p.mu.Lock()
	p.codes[code] = codeGrant{user: p.next, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri")}
	p.mu.Unlock()
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	switch {
	case p.IssParamOverride != "":
		v.Set("iss", p.IssParamOverride)
	case !p.OmitIssParam:
		v.Set("iss", p.Issuer)
	}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || secret != p.ClientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "invalid_client"})
		return
	}
	p.mu.Lock()
	g, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || r.PostForm.Get("redirect_uri") != g.redirectURI {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.Issuer, "sub": g.user.Subject, "aud": p.ClientID, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": g.nonce, "email": g.user.Email, "email_verified": g.user.EmailVerified, "name": g.user.Name,
	}
	if g.user.Groups != nil {
		claims["groups"] = g.user.Groups
	}
	if g.user.SID != "" {
		claims["sid"] = g.user.SID
	}
	if p.Tamper != nil {
		p.Tamper(claims)
	}
	writeJSON(w, map[string]any{"access_token": randString(), "token_type": "Bearer", "expires_in": 3600, "id_token": p.Sign(claims)})
}

// Sign signs claims with the IdP's key (RS256, kid set).
func (p *IdP) Sign(claims map[string]any) string {
	return SignWith(p.Key, p.KeyID, claims)
}

// SignWith signs claims with any RSA key.
func SignWith(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

// HS256 signs claims with a shared secret, for algorithm-confusion tests.
func HS256(secret []byte, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, nil)
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	obj, _ := signer.Sign(payload)
	s, _ := obj.CompactSerialize()
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func randString() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
