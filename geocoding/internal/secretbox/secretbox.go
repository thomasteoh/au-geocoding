// Package secretbox seals secrets at rest (OIDC client secrets, SAML SP
// private keys) with AES-256-GCM under the deployment's AUGEO_SECRET_KEY
// (auth.md A11). A sealed value is "v1:" + base64(nonce ‖ ciphertext).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrOpen is returned for any value that cannot be opened: wrong key,
// tampering, truncation or an unknown version. One error, so callers cannot
// leak which.
var ErrOpen = errors.New("secretbox: cannot open sealed value")

const prefix = "v1:"

// Box seals and opens values under one key, and computes keyed hashes with
// a subkey derived from it.
type Box struct {
	aead   cipher.AEAD
	macKey []byte
}

// ParseKey accepts a 32-byte key as 64 hex characters or standard/raw
// base64.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("secret key must be 32 bytes, hex or base64 encoded")
}

// New returns a Box for a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secretbox: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	mk := sha256.Sum256(append([]byte("augeo-mac\x00"), key...))
	return &Box{aead: aead, macKey: mk[:]}, nil
}

// MAC is HMAC-SHA256 of msg under the box's MAC subkey: a stable identifier
// for a value (such as an email address) that cannot be confirmed by
// guessing without the deployment's secret key.
func (b *Box) MAC(msg string) []byte {
	m := hmac.New(sha256.New, b.macKey)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// Seal encrypts plaintext. The empty string seals to the empty string so an
// unset secret stays visibly unset.
func (b *Box) Seal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// Open decrypts a value produced by Seal.
func (b *Box) Open(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if !strings.HasPrefix(sealed, prefix) {
		return "", ErrOpen
	}
	raw, err := base64.RawStdEncoding.DecodeString(sealed[len(prefix):])
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", ErrOpen
	}
	n := b.aead.NonceSize()
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", ErrOpen
	}
	return string(pt), nil
}
