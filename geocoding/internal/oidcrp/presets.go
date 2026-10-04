package oidcrp

import (
	"strings"
)

// Preset fills in what is known about an IdP so admins only enter the
// tenant/domain, client ID and secret (docs/auth.md "OIDC").
type Preset struct {
	Name string
	// IssuerHint is shown in the console, with {placeholders} for the admin.
	IssuerHint  string
	Scopes      []string
	GroupsClaim string
	// TrustEmail decides from verified ID token claims whether the email can
	// be used to link accounts (A2).
	TrustEmail func(c Claims) bool
	// MultiTenant marks issuers whose ID tokens carry a per-tenant iss
	// (Entra "common"/"organizations"); see verifyMultiTenant.
	MultiTenant func(issuer string) bool
}

func emailVerified(c Claims) bool { return c.EmailVerified.Bool() }

// Presets by name. The console lists them in this order.
var Presets = map[string]Preset{
	"google": {
		Name: "Google", IssuerHint: "https://accounts.google.com",
		Scopes: []string{"openid", "email", "profile"}, TrustEmail: emailVerified,
	},
	"entra": {
		Name: "Microsoft Entra ID", IssuerHint: "https://login.microsoftonline.com/{tenant-id}/v2.0",
		Scopes: []string{"openid", "email", "profile"}, GroupsClaim: "groups",
		// The email claim is user-editable in many tenants (nOAuth). Only
		// the optional xms_edov claim (email domain owner verified) makes it
		// usable for linking.
		TrustEmail: func(c Claims) bool { return c.XMSEdov.Bool() },
		MultiTenant: func(issuer string) bool {
			for _, t := range []string{"/common/", "/organizations/", "/consumers/"} {
				if strings.Contains(issuer, t) {
					return true
				}
			}
			return false
		},
	},
	"okta": {
		Name: "Okta", IssuerHint: "https://{your-org}.okta.com/oauth2/default",
		Scopes: []string{"openid", "email", "profile", "groups"}, GroupsClaim: "groups", TrustEmail: emailVerified,
	},
	"auth0": {
		Name: "Auth0", IssuerHint: "https://{tenant}.auth0.com/",
		Scopes: []string{"openid", "email", "profile"}, TrustEmail: emailVerified,
	},
	"keycloak": {
		Name: "Keycloak", IssuerHint: "https://{host}/realms/{realm}",
		Scopes: []string{"openid", "email", "profile"}, GroupsClaim: "groups", TrustEmail: emailVerified,
	},
	"gitlab": {
		Name: "GitLab", IssuerHint: "https://gitlab.com",
		Scopes: []string{"openid", "email", "profile"}, GroupsClaim: "groups", TrustEmail: emailVerified,
	},
	"zitadel": {
		Name: "ZITADEL", IssuerHint: "https://{instance}.zitadel.cloud",
		Scopes: []string{"openid", "email", "profile"}, TrustEmail: emailVerified,
	},
	"authentik": {
		Name: "authentik", IssuerHint: "https://{host}/application/o/{slug}/",
		Scopes: []string{"openid", "email", "profile"}, GroupsClaim: "groups", TrustEmail: emailVerified,
	},
	"generic": {
		Name: "Generic OpenID Connect", IssuerHint: "https://idp.example.com",
		Scopes: []string{"openid", "email", "profile"}, GroupsClaim: "groups", TrustEmail: emailVerified,
	},
}

// PresetOrder is the console display order.
var PresetOrder = []string{"google", "entra", "okta", "auth0", "keycloak", "gitlab", "zitadel", "authentik", "generic"}

// PresetFor returns the named preset, or generic.
func PresetFor(name string) Preset {
	if p, ok := Presets[name]; ok {
		return p
	}
	return Presets["generic"]
}
