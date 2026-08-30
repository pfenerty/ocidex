package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/matryer/is"
)

// testVerifier is the PKCE verifier every happy-path test signs in with.
const testVerifier = "the-verifier"

// fakeIssuer is a minimal spec-compliant OIDC issuer: discovery, JWKS and a
// token endpoint that actually enforces PKCE. Enforcing it here rather than
// stubbing a success is the point — it is what makes the mismatch test mean
// something.
type fakeIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	// challenge is what AuthURL sent; the token endpoint checks the verifier
	// presented at exchange time against it.
	challenge string
	// claims is the ID token payload, minus iss/aud/exp which are filled in.
	claims map[string]any
	// signWith overrides the signing key, to forge a token from a key the
	// JWKS does not publish.
	signWith *rsa.PrivateKey
	// tokenCalls counts exchanges that reached the issuer.
	tokenCalls int
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeIssuer{
		key: key,
		claims: map[string]any{
			"sub":   "sub-123",
			"email": "person@example.com",
			"name":  "A Person",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
			"jwks_uri":               f.srv.URL + "/jwks.json",
			// go-oidc reads this to decide which signing algorithms to accept.
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := f.key.PublicKey
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": "test-key",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(bigEndianExponent(pub.E)),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if f.challenge != "" && s256(r.PostFormValue("code_verifier")) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{
			"access_token": "opaque",
			"token_type":   "bearer",
			"id_token":     f.idToken(t),
		})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	return f
}

// idToken mints an RS256 ID token over the issuer's current claims.
func (f *fakeIssuer) idToken(t *testing.T) string {
	t.Helper()
	claims := map[string]any{
		"iss": f.srv.URL,
		"aud": "client-id",
		"exp": 9999999999,
		"iat": 1700000000,
	}
	for k, v := range f.claims {
		claims[k] = v
	}

	header := b64JSON(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	payload := b64JSON(t, claims)
	signing := header + "." + payload

	key := f.key
	if f.signWith != nil {
		key = f.signWith
	}
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIssuer) provider(t *testing.T) *OIDCProvider {
	t.Helper()
	p, err := NewOIDCProvider(context.Background(), OIDCConfig{
		Name:        "test",
		IssuerURL:   f.srv.URL,
		ClientID:    "client-id",
		RedirectURL: "http://localhost:8080/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}

	return p
}

// beginLogin runs AuthURL and records the challenge it sent, so the fake
// issuer can hold the exchange to it.
func (f *fakeIssuer) beginLogin(t *testing.T, p *OIDCProvider) {
	t.Helper()
	u, err := url.Parse(p.AuthURL("state-1", testVerifier))
	if err != nil {
		t.Fatal(err)
	}
	f.challenge = u.Query().Get("code_challenge")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func b64JSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return base64.RawURLEncoding.EncodeToString(raw)
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func bigEndianExponent(e int) []byte {
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}

	return b
}

func TestNewOIDCProvider_DiscoveryFailureIsFatal(t *testing.T) {
	is := is.New(t)
	// An issuer that is not there must stop startup, not defer the failure to
	// the first user who clicks the login button.
	_, err := NewOIDCProvider(context.Background(), OIDCConfig{
		Name:      "test",
		IssuerURL: "http://127.0.0.1:1/nope",
		ClientID:  "client-id",
	})
	is.True(err != nil)
	is.True(strings.Contains(err.Error(), "discovery"))
	is.True(strings.Contains(err.Error(), "http://127.0.0.1:1/nope"))
}

func TestNewOIDCProvider_RequiresNameAndClientID(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)

	_, err := NewOIDCProvider(context.Background(), OIDCConfig{IssuerURL: f.srv.URL, ClientID: "c"})
	is.True(err != nil)

	_, err = NewOIDCProvider(context.Background(), OIDCConfig{Name: "test", IssuerURL: f.srv.URL})
	is.True(err != nil)
}

func TestOIDCProvider_NameIsNamespaced(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	// Subjects are unique only within an issuer, so the stored provider key
	// has to say which issuer minted them.
	is.Equal(f.provider(t).Name(), "oidc:test")
}

func TestOIDCProvider_AuthURLSendsChallengeNotVerifier(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	p := f.provider(t)

	raw := p.AuthURL("state-1", "verifier-must-not-travel")
	u, err := url.Parse(raw)
	is.NoErr(err)

	is.Equal(u.Query().Get("code_challenge_method"), "S256")
	is.Equal(u.Query().Get("code_challenge"), s256("verifier-must-not-travel"))
	is.Equal(u.Query().Get("state"), "state-1")
	is.True(strings.Contains(u.Query().Get("scope"), "openid"))
	// The verifier is the secret half; only its hash may reach the issuer.
	is.True(!strings.Contains(raw, "verifier-must-not-travel"))
}

func TestOIDCProvider_ExchangeUsesSubClaim(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	p := f.provider(t)
	f.beginLogin(t, p)

	id, err := p.Exchange(context.Background(), "code", testVerifier)
	is.NoErr(err)
	is.Equal(id.Provider, "oidc:test")
	// sub, never email: email is mutable at most IdPs, so keying on it would
	// let an address change hand over someone else's account.
	is.Equal(id.Subject, "sub-123")
	is.Equal(id.Email, "person@example.com")
	is.Equal(id.DisplayName, "A Person")
}

func TestOIDCProvider_ExchangeRejectsMissingVerifier(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	p := f.provider(t)
	f.beginLogin(t, p)

	_, err := p.Exchange(context.Background(), "code", "")
	is.True(err != nil)
	is.True(strings.Contains(err.Error(), "PKCE"))
	// Refused locally: an issuer lax enough to accept the omission must never
	// get the chance to downgrade the flow.
	is.Equal(f.tokenCalls, 0)
}

func TestOIDCProvider_ExchangeRejectsMismatchedVerifier(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	p := f.provider(t)
	f.beginLogin(t, p)

	_, err := p.Exchange(context.Background(), "code", "a-different-verifier")
	is.True(err != nil)
	// The issuer refused it: x/oauth2 may retry once with the other client-auth
	// style, so the assertion is that the exchange happened, not how often.
	is.True(f.tokenCalls > 0)
}

func TestOIDCProvider_ExchangeRejectsForeignSignature(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	p := f.provider(t)
	f.beginLogin(t, p)

	forged, err := rsa.GenerateKey(rand.Reader, 2048)
	is.NoErr(err)
	f.signWith = forged

	_, err = p.Exchange(context.Background(), "code", testVerifier)
	is.True(err != nil)
	is.True(strings.Contains(err.Error(), "verifying id_token"))
}

func TestOIDCProvider_ExchangeRejectsMissingSub(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	p := f.provider(t)
	f.beginLogin(t, p)
	delete(f.claims, "sub")

	_, err := p.Exchange(context.Background(), "code", testVerifier)
	is.True(err != nil)
	is.True(strings.Contains(err.Error(), "sub"))
}

func TestOIDCProvider_DisplayNameFallsBack(t *testing.T) {
	is := is.New(t)
	f := newFakeIssuer(t)
	p := f.provider(t)
	f.beginLogin(t, p)

	// An issuer that releases no name is still usable; the account just shows
	// whatever it did release.
	delete(f.claims, "name")
	f.claims["preferred_username"] = "aperson"
	id, err := p.Exchange(context.Background(), "code", testVerifier)
	is.NoErr(err)
	is.Equal(id.DisplayName, "aperson")

	delete(f.claims, "preferred_username")
	id, err = p.Exchange(context.Background(), "code", testVerifier)
	is.NoErr(err)
	is.Equal(id.DisplayName, "person@example.com")
}
