package oidcrp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"

	"augeocoding/internal/identity"
)

// GitHubEndpoints locates GitHub. Zero values mean github.com; a connection
// whose Issuer is set is GitHub Enterprise Server at that base URL.
type GitHubEndpoints struct {
	AuthURL  string
	TokenURL string
	APIURL   string
}

func (g GitHubEndpoints) resolve(c identity.Connection) GitHubEndpoints {
	if g.AuthURL != "" {
		return g
	}
	if base := strings.TrimSuffix(c.Issuer, "/"); base != "" {
		return GitHubEndpoints{AuthURL: base + "/login/oauth/authorize", TokenURL: base + "/login/oauth/access_token", APIURL: base + "/api/v3"}
	}
	return GitHubEndpoints{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", APIURL: "https://api.github.com"}
}

func (g GitHubEndpoints) endpoint(c identity.Connection) oauth2.Endpoint {
	r := g.resolve(c)
	return oauth2.Endpoint{AuthURL: r.AuthURL, TokenURL: r.TokenURL, AuthStyle: oauth2.AuthStyleInParams}
}

func githubScopes(c identity.Connection) []string {
	s := []string{"read:user", "user:email"}
	if len(c.AllowedOrgs) > 0 {
		s = append(s, "read:org")
	}
	return s
}

func (rp *RP) githubCallback(ctx context.Context, c identity.Connection, f identity.Flow, code string) (identity.Assertion, error) {
	cfg := rp.oauthConfig(c, rp.GitHub.endpoint(c))
	tok, err := cfg.Exchange(rp.ctx(ctx), code, oauth2.VerifierOption(f.PKCEVerifier))
	if err != nil {
		return identity.Assertion{}, fmt.Errorf("%w: exchange: %v", ErrToken, err)
	}
	api := rp.GitHub.resolve(c).APIURL
	client := cfg.Client(rp.ctx(ctx), tok)

	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := getJSON(ctx, client, api+"/user", &user); err != nil || user.ID == 0 {
		return identity.Assertion{}, fmt.Errorf("%w: user: %v", ErrToken, err)
	}
	// /user's email field is the public profile email, which need not be
	// verified. /user/emails says which addresses GitHub verified.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, client, api+"/user/emails", &emails); err != nil {
		return identity.Assertion{}, fmt.Errorf("%w: emails: %v", ErrToken, err)
	}
	email, trusted := "", false
	for _, e := range emails {
		if e.Primary {
			email, trusted = e.Email, e.Verified
		}
	}
	if len(c.AllowedOrgs) > 0 {
		var orgs []struct {
			Login string `json:"login"`
		}
		if err := getJSON(ctx, client, api+"/user/orgs?per_page=100", &orgs); err != nil {
			return identity.Assertion{}, fmt.Errorf("%w: orgs: %v", ErrToken, err)
		}
		ok := false
		for _, o := range orgs {
			for _, allowed := range c.AllowedOrgs {
				ok = ok || strings.EqualFold(o.Login, allowed)
			}
		}
		if !ok {
			return identity.Assertion{}, &identity.Denial{Code: "github_org", Message: "Your GitHub account is not in an organisation this sign-in allows."}
		}
	}
	name := user.Name
	if name == "" {
		name = user.Login
	}
	return identity.Assertion{
		Connection:   c,
		Subject:      strconv.FormatInt(user.ID, 10), // logins can be renamed and reused; the ID cannot
		Email:        email,
		EmailTrusted: trusted || (c.TrustEmail && email != ""),
		Name:         truncate(name, 100),
	}, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}
