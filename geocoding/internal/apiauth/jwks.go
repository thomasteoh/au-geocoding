package apiauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// JWKSRefetchInterval is the minimum gap between remote fetches of one key
// set. Without it every forged token naming an unknown kid would make the
// server fetch the issuer's JWKS (an outbound request per inbound request).
const JWKSRefetchInterval = 30 * time.Second

// errNoKey is returned when no cached key verifies the token.
var errNoKey = errors.New("jwks: no matching key")

// cachedKeySet verifies JWS signatures against a cached JWKS. It goes to
// the network only when the token's kid is not in the cache (key rotation),
// and then at most once per JWKSRefetchInterval. A token whose kid is known
// but whose signature fails never triggers a fetch.
type cachedKeySet struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex // guards keys, lastFetch
	keys      []jose.JSONWebKey
	lastFetch time.Time
	fetchMu   sync.Mutex // serialises fetches
}

func newCachedKeySet(url string, client *http.Client) *cachedKeySet {
	return &cachedKeySet{url: url, client: client, now: time.Now}
}

// VerifySignature checks raw against the cached keys, refreshing them for an
// unknown kid (rate limited). It returns the verified payload.
func (k *cachedKeySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, signatureAlgs)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("jwks: want exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID

	k.mu.Lock()
	keys := k.keys
	k.mu.Unlock()
	if payload, known, err := verifyWith(jws, keys, kid); known {
		// The kid is cached (or the token names none and the cache is
		// populated): the answer stands, no refetch.
		return payload, err
	}
	if err := k.refresh(ctx); err != nil {
		return nil, err
	}
	k.mu.Lock()
	keys = k.keys
	k.mu.Unlock()
	payload, _, err := verifyWith(jws, keys, kid)
	return payload, err
}

// verifyWith tries the keys matching kid (all keys when kid is empty).
// known reports whether any candidate key was found, which is what decides
// whether a refetch could help.
func verifyWith(jws *jose.JSONWebSignature, keys []jose.JSONWebKey, kid string) (payload []byte, known bool, err error) {
	for _, key := range keys {
		if kid != "" && key.KeyID != kid {
			continue
		}
		known = true
		if p, err := jws.Verify(key); err == nil {
			return p, true, nil
		}
	}
	return nil, known, errNoKey
}

// refresh fetches the JWKS unless a fetch happened within the interval.
// Concurrent callers wait on one fetch rather than each issuing their own.
func (k *cachedKeySet) refresh(ctx context.Context) error {
	k.fetchMu.Lock()
	defer k.fetchMu.Unlock()
	k.mu.Lock()
	recent := !k.lastFetch.IsZero() && k.now().Sub(k.lastFetch) < JWKSRefetchInterval
	k.mu.Unlock()
	if recent {
		return nil // use what we have; the caller re-verifies and fails
	}
	keys, err := k.fetch(ctx)
	k.mu.Lock()
	defer k.mu.Unlock()
	// A failed fetch also starts the interval, so an unreachable JWKS is not
	// hammered either.
	k.lastFetch = k.now()
	if err != nil {
		return err
	}
	k.keys = keys
	return nil
}

func (k *cachedKeySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("jwks: decode: %w", err)
	}
	var out []jose.JSONWebKey
	for _, key := range set.Keys {
		if key.Use == "enc" || !key.Valid() || !key.IsPublic() {
			continue
		}
		out = append(out, key)
	}
	return out, nil
}
