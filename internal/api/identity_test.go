package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

// The link round trip goes out through the huma API and comes back through the
// browser-redirect callback, so it can only be tested against a router that has
// both. What these tests pin is the seam between them: the code that arrives at
// /auth/callback is linked onto the caller's account instead of signing someone
// in, and nothing but the signed state cookie decides which of the two happens.

const linkSessionToken = "session-linker"

// linkUser is the account doing the linking. It signs in with a cookie rather
// than a bearer token because finishIdentityLink reads the session directly.
var linkUser = service.AuthUser{ID: ownerUUID, DisplayName: "linker", Role: "member"}

func newLinkAuthService() *sessionAuthService {
	svc := &sessionAuthService{
		roster:   []service.AuthUser{linkUser},
		sessions: map[string]service.AuthUser{linkSessionToken: linkUser},
	}
	svc.buildAuthURL = func(_, state, _ string) (string, error) {
		return "https://issuer.example.com/authorize?state=" + state, nil
	}
	return svc
}

func newIdentityTestRouter(authSvc service.AuthService) http.Handler {
	h := api.NewHandler(nil, nil, authSvc, nil, nil, nil, nil, nil, nil, nil, &fakePinger{}, nil,
		&config.Config{
			Environment:       "development",
			SessionSecret:     strings.Repeat("k", 32),
			SessionMaxAgeDays: 7,
			FrontendURL:       "http://localhost:3000",
		})
	return api.NewRouter(h, "*", "", "")
}

func sessionCookie() *http.Cookie {
	return &http.Cookie{Name: "ocidex_session", Value: linkSessionToken}
}

// startLink drives POST /api/v1/auth/identities and returns the state cookie it
// set — the only thing the callback needs from this hop.
func startLink(t *testing.T, router http.Handler, provider string) *http.Cookie {
	t.Helper()
	is := is.New(t)

	body := strings.NewReader(fmt.Sprintf(`{"provider":%q}`, provider))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/identities", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(sessionCookie())

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	is.Equal(rec.Code, http.StatusOK)

	var out struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	is.NoErr(json.Unmarshal(rec.Body.Bytes(), &out))
	// The page navigates to this itself; a 3xx here would be followed into a
	// cross-origin request the fetch cannot use.
	is.True(strings.HasPrefix(out.AuthorizeURL, "https://issuer.example.com/authorize"))

	var state *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "ocidex_oauth_state" {
			state = c
		}
	}
	is.True(state != nil)

	return state
}

// finishLink presents a code at the callback with the given cookies.
func finishLink(router http.Handler, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=x", nil)
	for _, c := range cookies {
		req.AddCookie(c)
		if c.Name == "ocidex_oauth_state" {
			req.URL.RawQuery = "code=abc&state=" + c.Value
		}
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	return rec
}

// TestLinkRoundTripLinksInsteadOfSigningIn is the core of the story: the same
// callback that signs a person in links an identity instead when the state says
// so, and the sign-in exchange never runs.
func TestLinkRoundTripLinksInsteadOfSigningIn(t *testing.T) {
	is := is.New(t)

	authSvc := newLinkAuthService()
	var exchanged bool
	authSvc.exchange = func(string, string, string) (service.AuthUser, error) {
		exchanged = true
		return service.AuthUser{}, nil
	}
	router := newIdentityTestRouter(authSvc)

	state := startLink(t, router, "oidc:corp")
	rec := finishLink(router, state, sessionCookie())

	is.Equal(rec.Code, http.StatusSeeOther)
	is.True(strings.HasSuffix(rec.Header().Get("Location"), "/admin/account?link=ok"))
	is.Equal(authSvc.linked, []string{"oidc:corp"})
	// A link is not a sign-in: the code went to LinkIdentity, and the account
	// the browser was already using is untouched.
	is.True(!exchanged)
}

// TestLinkRoundTripReportsConflict covers the answer that matters to the person
// at the keyboard: an identity another account already holds is refused, and
// the account page is told why rather than being left to guess.
func TestLinkRoundTripReportsConflict(t *testing.T) {
	is := is.New(t)

	authSvc := newLinkAuthService()
	authSvc.linkErr = fmt.Errorf("identity oidc:corp is linked elsewhere: %w", service.ErrConflict)
	router := newIdentityTestRouter(authSvc)

	state := startLink(t, router, "oidc:corp")
	rec := finishLink(router, state, sessionCookie())

	is.Equal(rec.Code, http.StatusSeeOther)
	is.True(strings.HasSuffix(rec.Header().Get("Location"), "/admin/account?link=conflict"))
}

// TestLinkCallbackWithoutSessionIsRefused pins that a link needs a live
// session, not just a valid state cookie. The state says which account the trip
// started from, but it is not proof that the browser is still signed in as it.
func TestLinkCallbackWithoutSessionIsRefused(t *testing.T) {
	is := is.New(t)

	authSvc := newLinkAuthService()
	router := newIdentityTestRouter(authSvc)

	state := startLink(t, router, "oidc:corp")
	rec := finishLink(router, state)

	is.Equal(rec.Code, http.StatusUnauthorized)
	is.Equal(len(authSvc.linked), 0)
}

// TestUnlinkRefusesTheLastIdentity is the 409 the account page renders. The
// service decides it; this pins that the handler does not turn it into a 500.
func TestUnlinkRefusesTheLastIdentity(t *testing.T) {
	is := is.New(t)

	authSvc := newLinkAuthService()
	authSvc.unlinkErr = fmt.Errorf("last identity on the account: %w", service.ErrConflict)
	router := newIdentityTestRouter(authSvc)

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/auth/identities/"+testRegistryID, nil)
	req.AddCookie(sessionCookie())

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	is.Equal(rec.Code, http.StatusConflict)
}

// TestListMyIdentitiesIsSelfScoped checks the only route that reveals a subject:
// it answers from the session's own user, and takes no user from the caller.
func TestListMyIdentitiesIsSelfScoped(t *testing.T) {
	is := is.New(t)

	authSvc := newLinkAuthService()
	authSvc.identities = []service.LinkedIdentity{
		{ID: otherUUID, Provider: "github", Subject: "16961380"},
	}
	router := newIdentityTestRouter(authSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/identities", nil)
	req.AddCookie(sessionCookie())

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	is.Equal(rec.Code, http.StatusOK)

	var out struct {
		Identities []struct {
			Provider    string `json:"provider"`
			DisplayName string `json:"display_name"`
			Subject     string `json:"subject"`
		} `json:"identities"`
	}
	is.NoErr(json.Unmarshal(rec.Body.Bytes(), &out))
	is.Equal(len(out.Identities), 1)
	is.Equal(out.Identities[0].Provider, "github")
	is.Equal(out.Identities[0].DisplayName, "GitHub")
}

// TestListAuthProvidersIsPublic pins the one identity route that answers before
// anyone is signed in — the login page cannot render its buttons otherwise.
func TestListAuthProvidersIsPublic(t *testing.T) {
	is := is.New(t)

	router := newIdentityTestRouter(newLinkAuthService())

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil))
	is.Equal(rec.Code, http.StatusOK)

	var out struct {
		Providers []struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
			LoginPath   string `json:"login_path"`
		} `json:"providers"`
	}
	is.NoErr(json.Unmarshal(rec.Body.Bytes(), &out))
	is.Equal(len(out.Providers), 1)
	is.Equal(out.Providers[0].Name, "github")
	is.Equal(out.Providers[0].LoginPath, "/auth/login/github")
}
