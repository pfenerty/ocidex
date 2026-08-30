package tests

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/auth"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/devidp"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/service"
)

// oidcProviderKey is what the mock issuer's accounts are stored under. It has
// to match scripts/dev-auth.sh's OIDC_NAME, because the identity rows the rig
// seeds are keyed on it.
const oidcProviderKey = "oidc:mock"

// devPersonas mirrors scripts/dev-auth.sh's PERSONAS list, with the role each
// one is seeded with.
var devPersonas = []struct {
	name string
	role string
}{
	{"devadmin", "admin"},
	{"devowner", "member"},
	{"devsecurity", "member"},
	{"devviewer", "viewer"},
	{"devoutsider", "member"},
	{"devdeveloper", "member"},
}

// setupOIDCRig starts a mock issuer and an API server wired to it, and returns
// the API's base URL.
//
// The listener is created before the server so the OIDC redirect URI can name
// the port the API is about to listen on: an issuer redirects to a URL agreed
// in advance, so the address cannot be discovered after the fact.
func setupOIDCRig(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving api port: %v", err)
	}
	apiURL := "http://" + listener.Addr().String()

	idpSrv := httptest.NewServer(nil)
	idp, err := devidp.New(idpSrv.URL, nil)
	if err != nil {
		t.Fatalf("creating mock idp: %v", err)
	}
	idpSrv.Config.Handler = idp.Handler()
	t.Cleanup(idpSrv.Close)

	oidcProvider, err := auth.NewOIDCProvider(t.Context(), auth.OIDCConfig{
		Name:        "mock",
		IssuerURL:   idpSrv.URL,
		ClientID:    "ocidex-dev",
		RedirectURL: apiURL + "/auth/callback",
	})
	if err != nil {
		t.Fatalf("discovering mock idp: %v", err)
	}

	cfg := &config.Config{
		SessionSecret: testSessionSecret,
		Environment:   "development",
		FrontendURL:   "http://localhost:3200",
		// Without this the session is created already expired: the row's
		// expires_at is now + SessionMaxAgeDays, and the zero value makes
		// every sign-in succeed and every subsequent request 401.
		SessionMaxAgeDays: 7,
	}
	authSvc := service.NewAuthService(pool, cfg, event.NewBus(slog.Default()), []auth.Provider{
		auth.NewGitHubProvider("test-client", "test-secret", apiURL+"/auth/callback"),
		oidcProvider,
	})
	handler := api.NewHandler(
		service.NewSBOMService(pool, nil, nil), service.NewSearchService(pool), authSvc,
		service.NewRegistryService(pool), service.NewNamespaceService(pool),
		service.NewSourceService(pool), service.NewJobService(pool),
		service.NewEnrichJobService(pool, ""), service.NewWatchService(pool),
		service.NewClusterService(pool), pool, nil, cfg)

	srv := httptest.NewUnstartedServer(api.NewRouter(handler, "*", "", ""))
	if err := srv.Listener.Close(); err != nil {
		t.Fatalf("closing placeholder listener: %v", err)
	}
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)

	return apiURL
}

// seedOIDCUser creates an account already linked to the mock issuer, the way
// scripts/dev-auth.sh seeds its personas.
func seedOIDCUser(t *testing.T, pool *pgxpool.Pool, name, role string) {
	t.Helper()

	var id string
	err := pool.QueryRow(t.Context(),
		"INSERT INTO ocidex_user (display_name, role) VALUES ($1, $2) RETURNING id",
		name, role).Scan(&id)
	if err != nil {
		t.Fatalf("seeding user %s: %v", name, err)
	}
	if _, err := pool.Exec(t.Context(),
		"INSERT INTO user_identity (user_id, provider, subject) VALUES ($1, $2, $3)",
		id, oidcProviderKey, name); err != nil {
		t.Fatalf("seeding identity for %s: %v", name, err)
	}
}

// newFlowClient returns a client that keeps cookies but never follows a
// redirect on its own, so each hop of the sign-in can be asserted on.
func newFlowClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("creating cookie jar: %v", err)
	}

	return &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// signInAs drives a full sign-in: /auth/login -> the issuer's authorize
// endpoint -> /auth/callback, leaving a session cookie in the client's jar.
// It returns the authorize URL so a caller can assert on what the login hop
// committed to.
func signInAs(t *testing.T, client *http.Client, apiURL, persona string) string {
	t.Helper()

	loginResp := getNoFollow(t, client, apiURL+"/auth/login/"+oidcProviderKey)
	if loginResp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("login: got %d, want 307", loginResp.StatusCode)
	}
	authorizeURL := loginResp.Location()

	// login_hint is how the mock issuer is told which persona is at the
	// keyboard; a real IdP would show a password prompt here.
	hinted, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parsing authorize url: %v", err)
	}
	q := hinted.Query()
	q.Set("login_hint", persona)
	hinted.RawQuery = q.Encode()

	authResp := getNoFollow(t, client, hinted.String())
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: got %d, want 302", authResp.StatusCode)
	}
	cbResp := getNoFollow(t, client, authResp.Location())
	if cbResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: got %d, want 303", cbResp.StatusCode)
	}

	return authorizeURL
}

// httpResult is a response whose body has already been read and closed. Every
// hop in these flows is either a redirect or a small JSON document, so there is
// nothing to stream, and returning the bytes keeps the body from outliving the
// helper that opened it.
type httpResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Location is the redirect target, for the hops that have one.
func (r httpResult) Location() string { return r.Header.Get("Location") }

func getNoFollow(t *testing.T, client *http.Client, target string) httpResult {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("building request for %s: %v", target, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("requesting %s: %v", target, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response from %s: %v", target, err)
	}

	return httpResult{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}
}

// TestOIDCLoginEndToEnd is the acceptance test for the whole epic: a browser
// that has never seen an API key signs in through a real OIDC exchange and
// comes back as the right person.
func TestOIDCLoginEndToEnd(t *testing.T) {
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	apiURL := setupOIDCRig(t, pool)

	for _, persona := range devPersonas {
		seedOIDCUser(t, pool, persona.name, persona.role)
	}

	for _, persona := range devPersonas {
		t.Run(persona.name, func(t *testing.T) {
			is := is.New(t)
			client := newFlowClient(t)

			signInAs(t, client, apiURL, persona.name)

			meResp := getNoFollow(t, client, apiURL+"/api/v1/users/me")
			is.Equal(meResp.StatusCode, http.StatusOK)

			var me struct {
				DisplayName string `json:"display_name"`
				Role        string `json:"role"`
			}
			is.NoErr(json.Unmarshal(meResp.Body, &me))
			// The session landed on the seeded account, not a fresh one: the
			// display name and role are the ones the rig seeded.
			is.Equal(me.DisplayName, persona.name)
			is.Equal(me.Role, persona.role)
		})
	}
}

// TestOIDCLoginCreatesAccountOnFirstSignIn covers the other half of
// resolveIdentity: a subject with no identity row yet gets an account.
func TestOIDCLoginCreatesAccountOnFirstSignIn(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	apiURL := setupOIDCRig(t, pool)
	client := newFlowClient(t)

	signInAs(t, client, apiURL, "newcomer")

	var count int
	err := pool.QueryRow(t.Context(),
		"SELECT count(*) FROM user_identity WHERE provider = $1 AND subject = $2",
		oidcProviderKey, "newcomer").Scan(&count)
	is.NoErr(err)
	is.Equal(count, 1)

	meResp := getNoFollow(t, client, apiURL+"/api/v1/users/me")
	is.Equal(meResp.StatusCode, http.StatusOK)
}

// TestOIDCAuthorizeCarriesPKCEChallenge pins that the login redirect commits to
// PKCE. The mock issuer enforces it at the token endpoint, so a flow that sent
// no challenge would still pass the end-to-end test above — this is what makes
// the omission visible.
func TestOIDCAuthorizeCarriesPKCEChallenge(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	apiURL := setupOIDCRig(t, pool)
	seedOIDCUser(t, pool, "devadmin", "admin")

	authorizeURL := signInAs(t, newFlowClient(t), apiURL, "devadmin")

	parsed, err := url.Parse(authorizeURL)
	is.NoErr(err)
	is.Equal(parsed.Query().Get("code_challenge_method"), "S256")
	is.True(parsed.Query().Get("code_challenge") != "")
}

// TestOIDCCallbackRejectsForgedState is the negative control: an authorization
// code redeemed without the state cookie that started the flow is refused, so
// the callback cannot be driven by anyone but the browser that began it.
func TestOIDCCallbackRejectsForgedState(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	apiURL := setupOIDCRig(t, pool)
	seedOIDCUser(t, pool, "devadmin", "admin")

	// Run a real flow to obtain a genuine code, but keep its cookie jar.
	victim := newFlowClient(t)
	loginResp := getNoFollow(t, victim, apiURL+"/auth/login/"+oidcProviderKey)
	is.Equal(loginResp.StatusCode, http.StatusTemporaryRedirect)

	hinted, err := url.Parse(loginResp.Location())
	is.NoErr(err)
	q := hinted.Query()
	q.Set("login_hint", "devadmin")
	hinted.RawQuery = q.Encode()
	authResp := getNoFollow(t, victim, hinted.String())
	is.Equal(authResp.StatusCode, http.StatusFound)

	// A different browser presents the same callback URL.
	attacker := newFlowClient(t)
	resp := getNoFollow(t, attacker, authResp.Location())
	is.Equal(resp.StatusCode, http.StatusBadRequest)
}
