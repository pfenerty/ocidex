package api_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

// newAuthRouteTestRouter wires only the browser-redirect auth routes, which is
// all these tests are about.
func newAuthRouteTestRouter(authSvc *fakeAuthService) http.Handler {
	h := api.NewHandler(nil, nil, authSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		&config.Config{
			SessionSecret: strings.Repeat("k", 32),
			FrontendURL:   "http://localhost:3000",
			Environment:   "development",
		})

	r := chi.NewRouter()
	r.Get("/auth/login", h.HandleLogin)
	r.Get("/auth/login/{provider}", h.HandleLogin)
	r.Get("/auth/callback", h.HandleCallback)
	r.Get("/auth/callback/{provider}", h.HandleCallback)

	return r
}

func TestHandleLoginResolvesProvider(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		// The bare path is what every existing bookmark and the frontend's
		// current login link send; it must keep meaning GitHub.
		{name: "bare path defaults to github", path: "/auth/login", want: "github"},
		{name: "query parameter", path: "/auth/login?provider=oidc:corp", want: "oidc:corp"},
		{name: "path segment", path: "/auth/login/oidc:corp", want: "oidc:corp"},
		// The path is the more specific statement, so it wins.
		{name: "path beats query", path: "/auth/login/oidc:corp?provider=github", want: "oidc:corp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			var gotProvider, gotVerifier string
			authSvc := &fakeAuthService{
				buildAuthURL: func(provider, _, verifier string) (string, error) {
					gotProvider, gotVerifier = provider, verifier

					return "https://issuer.example.com/authorize", nil
				},
			}

			rec := httptest.NewRecorder()
			newAuthRouteTestRouter(authSvc).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			is.Equal(rec.Code, http.StatusTemporaryRedirect)
			is.Equal(gotProvider, tt.want)
			// A PKCE verifier is minted for every sign-in, whatever the
			// provider does with it.
			is.True(gotVerifier != "")
			// It is the secret half: it goes in the signed state cookie, never
			// to the issuer.
			is.True(!strings.Contains(rec.Header().Get("Location"), gotVerifier))
		})
	}
}

func TestHandleLoginRejectsUnknownProvider(t *testing.T) {
	is := is.New(t)

	authSvc := &fakeAuthService{
		buildAuthURL: func(_, _, _ string) (string, error) {
			return "", errors.New("unknown provider")
		},
	}

	rec := httptest.NewRecorder()
	newAuthRouteTestRouter(authSvc).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/auth/login/oidc:nope", nil))

	is.Equal(rec.Code, http.StatusBadRequest)
	// No state cookie is set for a sign-in that cannot begin.
	is.Equal(rec.Header().Get("Set-Cookie"), "")
}

// TestHandleCallbackUsesStateCookieProvider pins the rule that matters for a
// multi-provider callback: the signed cookie is the authority, not the URL. A
// caller who could pick the provider at callback time could otherwise present
// a code from a weak issuer against an account created by a strong one.
func TestHandleCallbackUsesStateCookieProvider(t *testing.T) {
	is := is.New(t)

	var loginProvider, loginVerifier string
	authSvc := &fakeAuthService{
		buildAuthURL: func(provider, _, verifier string) (string, error) {
			loginProvider, loginVerifier = provider, verifier

			return "https://issuer.example.com/authorize", nil
		},
	}
	router := newAuthRouteTestRouter(authSvc)

	// Begin a sign-in to get a genuine signed state cookie.
	loginRec := httptest.NewRecorder()
	router.ServeHTTP(loginRec, httptest.NewRequest(http.MethodGet, "/auth/login/oidc:corp", nil))
	is.Equal(loginProvider, "oidc:corp")

	var state *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		// The constant is unexported and this is an external test package.
		if c.Name == "ocidex_oauth_state" {
			state = c
		}
	}
	is.True(state != nil)

	var gotProvider, gotVerifier string
	authSvc.exchange = func(provider, _, verifier string) (service.AuthUser, error) {
		gotProvider, gotVerifier = provider, verifier

		return service.AuthUser{}, errors.New("stop here")
	}

	// Come back on the *github* path with the oidc:corp cookie.
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback/github?code=abc&state="+state.Value, nil)
	cbReq.AddCookie(state)
	router.ServeHTTP(httptest.NewRecorder(), cbReq)

	is.Equal(gotProvider, "oidc:corp")
	is.Equal(gotVerifier, loginVerifier)
}
