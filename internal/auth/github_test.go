package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
	"golang.org/x/oauth2"
)

// stubGitHub stands in for both endpoints a sign-in touches: the token exchange
// and the user API. Constructing the provider by field rather than through
// NewGitHubProvider is what lets the token endpoint be redirected too.
func stubGitHub(t *testing.T, userStatus int, userBody string) *GitHubProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"bearer"}`))
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(userStatus)
			_, _ = w.Write([]byte(userBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	return &GitHubProvider{
		oauth2: &oauth2.Config{
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "http://localhost/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  srv.URL + "/authorize",
				TokenURL: srv.URL + "/token",
			},
		},
		userAPI: srv.URL + "/user",
		client:  srv.Client(),
	}
}

func TestGitHubProvider_Name(t *testing.T) {
	is := is.New(t)
	is.Equal(NewGitHubProvider("id", "secret", "url").Name(), "github")
}

func TestGitHubProvider_AuthURLIgnoresVerifier(t *testing.T) {
	is := is.New(t)
	p := stubGitHub(t, http.StatusOK, "{}")
	// A PKCE verifier must not leak into a flow that does not use PKCE: sending
	// the raw secret as a query parameter would put it in GitHub's logs.
	with := p.AuthURL("state-1", "verifier-that-must-not-appear")
	without := p.AuthURL("state-1", "")
	is.Equal(with, without)
}

func TestGitHubProvider_ExchangeUsesNumericIDAsSubject(t *testing.T) {
	is := is.New(t)
	p := stubGitHub(t, http.StatusOK, `{"id":16961380,"login":"pfenerty","email":"a@example.com"}`)

	id, err := p.Exchange(context.Background(), "code", "verifier")
	is.NoErr(err)
	is.Equal(id.Provider, "github")
	// The login is cosmetic; the numeric id is the key. Keying on a re-assignable
	// login would hand the account to whoever claimed the name next.
	is.Equal(id.Subject, "16961380")
	is.Equal(id.DisplayName, "pfenerty")
	is.Equal(id.Email, "a@example.com")
}

func TestGitHubProvider_ExchangeSurfacesUserAPIFailure(t *testing.T) {
	is := is.New(t)
	p := stubGitHub(t, http.StatusUnauthorized, `{}`)

	_, err := p.Exchange(context.Background(), "code", "")
	is.True(err != nil)
}
