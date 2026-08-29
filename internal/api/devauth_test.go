package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

// The dev session mint is the one operation whose *absence* is the contract.
// It exists so the browser rig drives production's cookie path instead of the
// Bearer shortcut; it must not exist anywhere else. Both halves are asserted
// here — the production build has no such route, and the development build
// mints a cookie that OptionalAuthenticate then resolves through
// ValidateSession, which is the whole point of minting one.

// sessionAuthService is fakeAuthService with the two session calls the mint
// endpoint uses actually working, plus a roster to look a persona up in.
type sessionAuthService struct {
	fakeAuthService
	roster   []service.AuthUser
	sessions map[string]service.AuthUser
	minted   int
}

func (f *sessionAuthService) ListUsers(_ context.Context) ([]service.AuthUser, error) {
	return f.roster, nil
}

func (f *sessionAuthService) CreateSession(_ context.Context, userID pgtype.UUID) (string, error) {
	for _, u := range f.roster {
		if u.ID == userID {
			f.minted++
			token := "session-" + u.GitHubUsername
			f.sessions[token] = u
			return token, nil
		}
	}
	return "", errors.New("no such user")
}

func (f *sessionAuthService) ValidateSession(_ context.Context, token string) (service.AuthUser, error) {
	if u, ok := f.sessions[token]; ok {
		return u, nil
	}
	return service.AuthUser{}, errors.New("invalid session")
}

func personaID(b byte) pgtype.UUID {
	var u pgtype.UUID
	for i := range u.Bytes {
		u.Bytes[i] = b
	}
	u.Valid = true
	return u
}

func devPersonas() []service.AuthUser {
	return []service.AuthUser{
		{ID: personaID(0x11), GitHubUsername: "devadmin", Role: "admin"},
		{ID: personaID(0x22), GitHubUsername: "devviewer", Role: "viewer"},
	}
}

func newDevAuthService() *sessionAuthService {
	return &sessionAuthService{
		roster:   devPersonas(),
		sessions: map[string]service.AuthUser{},
	}
}

// devConfig is the config a development build runs with. SessionMaxAgeDays is
// non-zero so the emitted cookie carries a real Max-Age rather than a
// session-only one, matching HandleCallback.
func devConfig(env string) *config.Config {
	return &config.Config{
		Environment:       env,
		SessionSecret:     strings.Repeat("k", 32),
		SessionMaxAgeDays: 7,
	}
}

func newDevRouter(authSvc service.AuthService, env string) http.Handler {
	h := api.NewHandler(nil, nil, authSvc, nil, &fakeNamespaceService{}, &fakeSourceService{},
		nil, nil, nil, nil, &fakePinger{}, nil, devConfig(env))
	return api.NewRouter(h, "*", "", "")
}

// devSpec is the OpenAPI spec of a router built with a development config —
// the counterpart to conformanceSpec, which builds one with no config at all.
func devSpec() *huma.OpenAPI {
	h := api.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		devConfig("development"))
	_ = api.NewRouter(h, "*", "", "")
	return h.API().OpenAPI()
}

// TestDevSessionAbsentInProduction is the load-bearing half. The route must be
// absent from the router, not merely refused by it: a 403 would still be an
// endpoint an attacker could probe, and the operation would still appear in
// web/openapi.json and docs/AUTH_MATRIX.md.
func TestDevSessionAbsentInProduction(t *testing.T) {
	is := is.New(t)

	router := newDevRouter(newDevAuthService(), "production")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, newConformanceRequest(http.MethodPost, "/api/v1/dev/session"))
	is.Equal(rec.Code, http.StatusNotFound) // dev session mint reachable in a production build
}

// TestDevSessionAbsentFromProductionSpec asserts the same absence at the spec
// level, which is what keeps the operation out of web/openapi.json and out of
// the generated auth matrix.
func TestDevSessionAbsentFromProductionSpec(t *testing.T) {
	is := is.New(t)

	for _, row := range conformanceSpec() {
		is.True(row.OperationID != "dev-mint-session") // dev session mint present in the production spec
	}

	rows := api.AuthMatrixRows(devSpec())
	found := false
	for _, row := range rows {
		if row.OperationID == "dev-mint-session" {
			found = true
			is.True(row.Declared)                     // dev session mint registered without an authRules row
			is.Equal(row.Rule.Class, api.ClassPublic) // dev session mint is not public-class
			is.True(row.Rule.DevOnly)                 // dev session mint not marked DevOnly
		}
	}
	is.True(found) // dev session mint absent from a development spec
}

// TestDevSessionMintsResolvableCookie is the reason the endpoint exists: the
// cookie it hands back must travel back through OptionalAuthenticate and
// ValidateSession, the path production browsers take and the Bearer shortcut
// never does.
func TestDevSessionMintsResolvableCookie(t *testing.T) {
	is := is.New(t)

	authSvc := newDevAuthService()
	router := newDevRouter(authSvc, "development")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/session",
		strings.NewReader(`{"username":"devviewer"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	is.Equal(rec.Code, http.StatusOK) // minting a session for a seeded persona

	cookies := rec.Result().Cookies() //nolint:bodyclose // httptest recorder
	var session *http.Cookie
	for _, c := range cookies {
		if c.Name == "ocidex_session" {
			session = c
		}
	}
	is.True(session != nil)           // no session cookie in the response
	is.True(session.HttpOnly)         // session cookie is readable from JS
	is.True(!session.Secure)          // Secure would stop the http dev rig from ever sending it back
	is.Equal(session.MaxAge, 7*86400) // cookie max-age does not follow SessionMaxAgeDays
	is.Equal(authSvc.minted, 1)       // session was not created through CreateSession

	// The round trip: the cookie alone must authenticate the next request.
	me := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	me.AddCookie(session)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, me)
	is.Equal(rec2.Code, http.StatusOK) // minted cookie did not resolve via ValidateSession
	is.True(strings.Contains(rec2.Body.String(), "devviewer"))
}

// TestDevSessionUnknownPersona keeps the endpoint from being a way to conjure a
// principal that was never seeded.
func TestDevSessionUnknownPersona(t *testing.T) {
	is := is.New(t)

	authSvc := newDevAuthService()
	router := newDevRouter(authSvc, "development")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/session",
		strings.NewReader(`{"username":"nobody"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	is.Equal(rec.Code, http.StatusNotFound) // unknown persona was minted a session
	is.Equal(authSvc.minted, 0)             // session created for a persona that does not exist
}
