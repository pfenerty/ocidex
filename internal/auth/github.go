package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// ProviderGitHub is the issuer key for the GitHub OAuth app.
//
// It is not namespaced "oidc:github" because GitHub is not reached as an OIDC
// issuer here: there is no discovery document and no ID token, just the OAuth2
// code flow followed by a call to the user API. Its subjects therefore live in
// a namespace of their own, and migration 00069 backfilled them under this
// exact name.
const ProviderGitHub = "github"

const githubUserAPI = "https://api.github.com/user"

// GitHubProvider authenticates against github.com's OAuth app.
type GitHubProvider struct {
	oauth2 *oauth2.Config
	// userAPI is the endpoint to read the signed-in user from. It is a field
	// only so tests can point it at a stub; production never sets it.
	userAPI string
	client  *http.Client
}

// NewGitHubProvider builds the GitHub provider from an OAuth app's credentials.
func NewGitHubProvider(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		oauth2: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"read:user"},
			Endpoint:     github.Endpoint,
		},
		userAPI: githubUserAPI,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns the issuer key, "github".
func (p *GitHubProvider) Name() string { return ProviderGitHub }

// AuthURL builds the github.com authorize URL. The PKCE verifier is ignored:
// the OAuth app flow is authenticated by the client secret, and sending an
// unsolicited code_challenge would only add a parameter GitHub discards.
func (p *GitHubProvider) AuthURL(state, _ string) string {
	return p.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange redeems the code and reads the user it belongs to.
//
// The subject is GitHub's numeric user id rendered as text, never the login:
// logins are re-assignable, and keying an account on one would hand the account
// to whoever claimed the name next.
func (p *GitHubProvider) Exchange(ctx context.Context, code, _ string) (Identity, error) {
	token, err := p.oauth2.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("exchanging oauth code: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userAPI, nil)
	if err != nil {
		return Identity{}, fmt.Errorf("building github user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("fetching github user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("github user API returned %d", resp.StatusCode)
	}

	var ghUser struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		return Identity{}, fmt.Errorf("decoding github user: %w", err)
	}

	return Identity{
		Provider:    ProviderGitHub,
		Subject:     strconv.FormatInt(ghUser.ID, 10),
		Email:       ghUser.Email,
		DisplayName: ghUser.Login,
	}, nil
}
