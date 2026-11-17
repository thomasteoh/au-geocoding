package apiauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"augeocoding/internal/authtest"
	"augeocoding/internal/publicapi"
)

// countingJWKS serves key's public half and counts fetches.
func countingJWKS(t *testing.T, key *rsa.PrivateKey, kid string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}}}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestForgedTokensDoNotRefetchJWKS(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	srv, fetches := countingJWKS(t, f.idp.Key, f.idp.KeyID)
	regs, _ := f.ids.JWTIssuers(ctx, f.org.ID)
	regs[0].JWKSURL = srv.URL
	if _, err := f.ids.SaveJWTIssuer(ctx, regs[0]); err != nil {
		t.Fatal(err)
	}
	bearer := func(tok string) error {
		_, err := f.call(t, map[string]string{"Authorization": "Bearer " + tok})
		return err
	}
	if err := bearer(f.idp.Sign(f.claims())); err != nil {
		t.Fatalf("valid token: %v %v", err, f.reasons)
	}
	if fetches.Load() != 1 {
		t.Fatalf("first verify fetched %d times", fetches.Load())
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for i := 0; i < 20; i++ {
		// Known kid, wrong key: never a refetch.
		if err := bearer(authtest.SignWith(other, f.idp.KeyID, f.claims())); !errors.Is(err, publicapi.ErrInvalidKey) {
			t.Fatalf("forged (known kid) accepted: %v", err)
		}
		// Unknown kid: refetch allowed at most once per interval, and the
		// first fetch was just now.
		if err := bearer(authtest.SignWith(other, "rotated-"+string(rune('a'+i)), f.claims())); !errors.Is(err, publicapi.ErrInvalidKey) {
			t.Fatalf("forged (unknown kid) accepted: %v", err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("40 forged tokens caused %d JWKS fetches, want 1 in total", fetches.Load())
	}
	if err := bearer(f.idp.Sign(f.claims())); err != nil {
		t.Fatalf("valid token after forgeries: %v", err)
	}
}

func TestCachedKeySetRefetchInterval(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, fetches := countingJWKS(t, key, "k1")
	ks := newCachedKeySet(srv.URL, srv.Client())
	clock := time.Now()
	ks.now = func() time.Time { return clock }
	ctx := context.Background()
	good := authtest.SignWith(key, "k1", map[string]any{"sub": "x"})
	if _, err := ks.VerifySignature(ctx, good); err != nil {
		t.Fatal(err)
	}
	unknown := authtest.SignWith(key, "k2", map[string]any{"sub": "x"})
	for i := 0; i < 5; i++ {
		if _, err := ks.VerifySignature(ctx, unknown); err == nil {
			t.Fatal("unknown kid verified")
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetches within interval: %d", fetches.Load())
	}
	clock = clock.Add(JWKSRefetchInterval + time.Second)
	ks.VerifySignature(ctx, unknown)
	ks.VerifySignature(ctx, unknown)
	if fetches.Load() != 2 {
		t.Fatalf("fetches after interval: %d, want 2", fetches.Load())
	}
	// A known kid still verifies from cache with no fetch.
	if _, err := ks.VerifySignature(ctx, good); err != nil || fetches.Load() != 2 {
		t.Fatalf("cached verify: %v, fetches %d", err, fetches.Load())
	}
}

func TestBearerIPLimiterBeforeVerification(t *testing.T) {
	f := setup(t)
	f.auth.BearerIPLimiter = publicapi.NewRateLimiter(0.0001, 2)
	for i := 0; i < 2; i++ {
		if _, err := f.call(t, map[string]string{"Authorization": "Bearer not.a.jwt"}); !errors.Is(err, publicapi.ErrInvalidKey) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	before := len(f.reasons)
	if _, err := f.call(t, map[string]string{"Authorization": "Bearer not.a.jwt"}); !errors.Is(err, publicapi.ErrRateLimited) {
		t.Fatalf("third forged token from one IP: %v", err)
	}
	if len(f.reasons) != before {
		t.Fatal("rate-limited token was still parsed/verified")
	}
}
