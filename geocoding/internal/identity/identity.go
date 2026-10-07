// Package identity is the people side of au-geocoder: users, orgs,
// memberships, SSO connections, verified domains, sessions, login flows,
// passkeys, SCIM tokens, JWT issuers and the audit log (docs/auth.md).
//
// Tenant isolation lives here, not in handlers: every org-scoped method takes
// the org ID and puts it in the WHERE clause, so a handler that passes an
// object ID from a URL can never reach another org's row (auth.md A5).
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"augeocoding/internal/secretbox"
)

// Errors returned by the store. Handlers map ErrNotFound to 404 whether the
// row is missing or belongs to another org, so existence never leaks.
var (
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("already exists")
	ErrLastOwner = errors.New("an org must keep at least one owner")
	ErrInvalid   = errors.New("invalid value")
)

// Role is an org role. Order matters: a higher value can do everything a lower
// one can.
type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleDeveloper
	RoleAdmin
	RoleOwner
)

// ParseRole parses a role name. Unknown names are RoleNone.
func ParseRole(s string) Role {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer":
		return RoleViewer
	case "developer":
		return RoleDeveloper
	case "admin":
		return RoleAdmin
	case "owner":
		return RoleOwner
	}
	return RoleNone
}

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleDeveloper:
		return "developer"
	case RoleAdmin:
		return "admin"
	case RoleOwner:
		return "owner"
	}
	return ""
}

// AllRoles lists the assignable roles, lowest first.
var AllRoles = []Role{RoleViewer, RoleDeveloper, RoleAdmin, RoleOwner}

// Store is the identity store over app.db.
type Store struct {
	db  *sql.DB
	box *secretbox.Box
	// DefaultOrgTier is the quota tier new orgs get (one of ValidTiers;
	// empty means demo). Set once at boot.
	DefaultOrgTier string
}

// New migrates the identity schema on db and returns a store. box seals
// client secrets and SAML keys; it may be nil when the console is disabled,
// in which case methods that need it return an error.
func New(db *sql.DB, box *secretbox.Box) (*Store, error) {
	if err := migrate(db); err != nil {
		return nil, err
	}
	return &Store{db: db, box: box}, nil
}

// DB exposes the handle for packages that keep their own tables in app.db.
func (s *Store) DB() *sql.DB { return s.db }

// Box exposes the secret box (nil when the console is disabled).
func (s *Store) Box() *secretbox.Box { return s.box }

var errNoBox = errors.New("identity: AUGEO_SECRET_KEY is not configured")

func (s *Store) seal(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if s.box == nil {
		return "", errNoBox
	}
	return s.box.Seal(v)
}

func (s *Store) open(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if s.box == nil {
		return "", errNoBox
	}
	return s.box.Open(v)
}

// clock is replaceable in tests.
var clock = func() time.Time { return time.Now().UTC() }

func now() string { return clock().Format(time.RFC3339Nano) }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func parseNullTS(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := parseTS(s.String)
	return &t
}

// RandomToken returns n random bytes, URL-safe base64 encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken is the stored form of a bearer secret (session IDs, SCIM tokens,
// flow states). These are 256-bit random values, so a fast hash is right.
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// EmailDomain returns the lower-cased domain of an email, or "".
func EmailDomain(email string) string {
	i := strings.LastIndexByte(email, '@')
	if i < 0 || i == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[i+1:])
}

// NormaliseEmail trims and lower-cases an email address.
func NormaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidEmail is a deliberately loose syntactic check: one @, a dot in the
// domain, no spaces. IdPs are the authority on whether an address is real.
func ValidEmail(email string) bool {
	if len(email) > 254 || strings.ContainsAny(email, " \t\r\n<>\"") {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	return strings.Contains(email[at+1:], ".") && strings.Count(email, "@") == 1
}
