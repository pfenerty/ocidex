package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
)

// TestSessionCookieSameSite checks the SameSite and Secure attributes on the
// session cookie follow SESSION_COOKIE_SAMESITE. Logout is the probe: it sets
// the cookie through the same helper as the OAuth callback, so the two cannot
// disagree.
func TestSessionCookieSameSite(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		sameSite   string
		want       http.SameSite
		wantSecure bool
	}{
		{"unset defaults to lax in development", "development", "", http.SameSiteLaxMode, false},
		{"unset defaults to lax in production", "production", "", http.SameSiteLaxMode, true},
		{"lax in production", "production", config.SameSiteLax, http.SameSiteLaxMode, true},
		{"strict", "production", config.SameSiteStrict, http.SameSiteStrictMode, true},
		{"none is secure", "production", config.SameSiteNone, http.SameSiteNoneMode, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			h := api.NewHandler(nil, nil, &fakeAuthService{}, nil, nil, nil, nil, nil, nil, nil, &fakePinger{}, nil,
				&config.Config{
					Environment:           tt.env,
					SessionSecret:         strings.Repeat("k", 32),
					SessionMaxAgeDays:     7,
					SessionCookieSameSite: tt.sameSite,
					FrontendURL:           "http://localhost:3000",
				})
			router := api.NewRouter(h, "*", "", "")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))

			var session *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "ocidex_session" {
					session = c
				}
			}
			is.True(session != nil) // logout sets an expired session cookie
			is.Equal(session.SameSite, tt.want)
			is.Equal(session.Secure, tt.wantSecure)
			is.True(session.HttpOnly)
		})
	}
}
