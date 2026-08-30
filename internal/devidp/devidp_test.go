package devidp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/matryer/is"
)

const testPersona = "devadmin"

func newTestIssuer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(nil)
	idp, err := New(srv.URL, []string{"devadmin", "devviewer"})
	if err != nil {
		t.Fatalf("creating issuer: %v", err)
	}
	srv.Config.Handler = idp.Handler()
	t.Cleanup(srv.Close)

	return srv
}

// authorize runs the authorize hop and returns the code it handed back.
func authorize(t *testing.T, srv *httptest.Server, challenge string) string {
	t.Helper()

	q := url.Values{
		"client_id":     {"ocidex-dev"},
		"redirect_uri":  {"http://client.test/auth/callback"},
		"response_type": {"code"},
		"state":         {"state-1"},
		"login_hint":    {testPersona},
	}
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/authorize?" + q.Encode()) //nolint:noctx // test helper
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: got %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing redirect: %v", err)
	}
	if got := loc.Query().Get("state"); got != "state-1" {
		t.Fatalf("state round trip: got %q", got)
	}

	return loc.Query().Get("code")
}

// redeem posts to the token endpoint and returns the status and body.
func redeem(t *testing.T, srv *httptest.Server, form url.Values) (int, map[string]any) {
	t.Helper()

	resp, err := srv.Client().PostForm(srv.URL+"/token", form) //nolint:noctx // test helper
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}

	return resp.StatusCode, body
}

func TestDiscoveryAdvertisesItsOwnIssuer(t *testing.T) {
	is := is.New(t)
	srv := newTestIssuer(t)

	resp, err := srv.Client().Get(srv.URL + "/.well-known/openid-configuration") //nolint:noctx // test
	is.NoErr(err)
	defer resp.Body.Close()

	var doc map[string]any
	is.NoErr(json.NewDecoder(resp.Body).Decode(&doc))
	// go-oidc rejects a token whose iss differs from the discovery URL, so
	// this equality is the whole contract with the client.
	is.Equal(doc["issuer"], srv.URL)
	is.Equal(doc["token_endpoint"], srv.URL+"/token")
	is.Equal(doc["jwks_uri"], srv.URL+"/jwks.json")
}

func TestAuthorizeWithoutHintOffersPersonas(t *testing.T) {
	is := is.New(t)
	srv := newTestIssuer(t)

	resp, err := srv.Client().Get(srv.URL + //nolint:noctx // test
		"/authorize?redirect_uri=http://client.test/cb&state=s")
	is.NoErr(err)
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	page := string(buf[:n])

	is.Equal(resp.StatusCode, http.StatusOK)
	is.True(strings.Contains(page, "login_hint=devadmin"))
	is.True(strings.Contains(page, "login_hint=devviewer"))
	// The picker is a step in the flow, not a second entry point: every
	// parameter the client sent has to survive it.
	is.True(strings.Contains(page, "state=s"))
}

func TestTokenExchangeReturnsIDTokenForSubject(t *testing.T) {
	is := is.New(t)
	srv := newTestIssuer(t)

	code := authorize(t, srv, s256("v"))
	status, body := redeem(t, srv, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://client.test/auth/callback"},
		"client_id":     {"ocidex-dev"},
		"code_verifier": {"v"},
	})

	is.Equal(status, http.StatusOK)
	raw, ok := body["id_token"].(string)
	is.True(ok)

	parts := strings.Split(raw, ".")
	is.Equal(len(parts), 3)
	claims := decodeSegment(t, parts[1])
	is.Equal(claims["sub"], "devadmin")
	is.Equal(claims["iss"], srv.URL)
	is.Equal(claims["aud"], "ocidex-dev")
	is.Equal(claims["preferred_username"], "devadmin")
}

func TestTokenExchangeRejectsBadVerifier(t *testing.T) {
	is := is.New(t)
	srv := newTestIssuer(t)

	code := authorize(t, srv, s256("v"))
	// PKCE is enforced for real: a mock that rubber-stamped the verifier would
	// let a client ship with PKCE quietly broken.
	status, body := redeem(t, srv, url.Values{
		"code":          {code},
		"client_id":     {"ocidex-dev"},
		"code_verifier": {"wrong"},
	})

	is.Equal(status, http.StatusBadRequest)
	is.Equal(body["error"], "invalid_grant")
}

func TestAuthorizationCodesAreSingleUse(t *testing.T) {
	is := is.New(t)
	srv := newTestIssuer(t)

	code := authorize(t, srv, "")
	form := url.Values{"code": {code}, "client_id": {"ocidex-dev"}}

	first, _ := redeem(t, srv, form)
	is.Equal(first, http.StatusOK)

	second, body := redeem(t, srv, form)
	is.Equal(second, http.StatusBadRequest)
	is.Equal(body["error"], "invalid_grant")
}

func TestTokenExchangeRejectsMismatchedRedirectURI(t *testing.T) {
	is := is.New(t)
	srv := newTestIssuer(t)

	code := authorize(t, srv, "")
	status, _ := redeem(t, srv, url.Values{
		"code":         {code},
		"client_id":    {"ocidex-dev"},
		"redirect_uri": {"http://evil.test/cb"},
	})

	is.Equal(status, http.StatusBadRequest)
}

// TestMockIDPShipsInNoImage is the guard for the one rule this package must
// never break. An issuer that signs with an ephemeral key and hands a session
// to whoever asks is harmless on a laptop and a full authentication bypass in
// a cluster.
func TestMockIDPShipsInNoImage(t *testing.T) {
	is := is.New(t)

	dockerfile, err := os.ReadFile("../../docker/Dockerfile")
	is.NoErr(err)

	for _, line := range strings.Split(string(dockerfile), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "mock-idp") {
			t.Fatalf("docker/Dockerfile references mock-idp: %q", trimmed)
		}
	}
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decoding jwt segment: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshalling claims: %v", err)
	}

	return claims
}
