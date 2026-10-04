package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"augeocoding/internal/identity"
)

// ProviderSpec declares a platform connection in AUGEO_AUTH_PROVIDERS_FILE
// (docs/auth.md "Configuration"). Secrets come from a file or an env var,
// never inline in the JSON.
type ProviderSpec struct {
	Slug             string   `json:"slug"`
	Kind             string   `json:"kind"` // oidc (default) or github
	Preset           string   `json:"preset"`
	Name             string   `json:"name"`
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	ClientSecretEnv  string   `json:"client_secret_env"`
	Scopes           []string `json:"scopes"`
	GroupsClaim      string   `json:"groups_claim"`
	TrustEmail       bool     `json:"trust_email"`
	AllowedOrgs      []string `json:"allowed_orgs"`
	Disabled         bool     `json:"disabled"`
}

// LoadProviders upserts the file's platform connections, marked managed so
// the console shows them read-only.
func LoadProviders(ctx context.Context, ids *identity.Store, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var specs []ProviderSpec
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&specs); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, p := range specs {
		secret := ""
		switch {
		case p.ClientSecretFile != "":
			sb, err := os.ReadFile(p.ClientSecretFile)
			if err != nil {
				return fmt.Errorf("provider %s: %w", p.Slug, err)
			}
			secret = strings.TrimSpace(string(sb))
		case p.ClientSecretEnv != "":
			secret = os.Getenv(p.ClientSecretEnv)
		}
		if secret == "" {
			return fmt.Errorf("provider %s: client secret is empty (set client_secret_file or client_secret_env)", p.Slug)
		}
		kind := p.Kind
		if kind == "" {
			kind = identity.KindOIDC
		}
		preset := p.Preset
		if preset == "" {
			preset = "generic"
		}
		issuer := p.Issuer
		if issuer == "" && preset == "google" {
			issuer = "https://accounts.google.com"
		}
		c := identity.Connection{Slug: p.Slug, Kind: kind, Preset: preset, Name: p.Name, Enabled: !p.Disabled, Issuer: issuer,
			ClientID: p.ClientID, ClientSecret: secret, Scopes: p.Scopes, GroupsClaim: p.GroupsClaim, TrustEmail: p.TrustEmail,
			AllowedOrgs: p.AllowedOrgs, Managed: true}
		existing, err := ids.ConnectionBySlug(ctx, p.Slug)
		switch {
		case errors.Is(err, identity.ErrNotFound):
		case err != nil:
			return err
		case existing.OrgID != 0:
			return fmt.Errorf("provider %s: slug is used by an org connection", p.Slug)
		default:
			c.ID = existing.ID
		}
		if _, err := ids.SaveConnection(ctx, c); err != nil {
			return fmt.Errorf("provider %s: %w", p.Slug, err)
		}
	}
	return nil
}
