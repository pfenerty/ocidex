// Package devidp is a mock OpenID Connect issuer for local development and
// tests.
//
// It exists because the /auth routes had nothing exercising them: the dev rig
// authenticates by API key, and no GitHub OAuth app exists for a developer to
// point it at. Once there is a generic OIDC provider (ocidex-iqkt.3) the
// protocol itself is mockable, and this is the mock.
//
// It is emphatically not a security boundary. It signs with a key generated at
// startup, accepts any client_id and any subject, and hands out a session to
// whoever asks. It must never be reachable from anything but a developer's own
// machine or a test process, which is why it lives behind cmd/mock-idp and no
// production binary imports it.
package devidp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// codeTTL bounds how long an authorization code stays redeemable. Short
// because a real issuer's is short, and a test that leans on a stale code
// should fail here rather than in production.
const codeTTL = 2 * time.Minute

// signingKID is the only key id this issuer ever publishes.
const signingKID = "mock-idp"

const (
	algRS256    = "RS256"
	errField    = "error"
	errBadGrant = "invalid_grant"
	errBadReq   = "invalid_request"
	errServer   = "server_error"
)

// pendingCode is an issued-but-unredeemed authorization code.
type pendingCode struct {
	subject     string
	nonce       string
	redirectURI string
	challenge   string
	expiresAt   time.Time
}

// Server is the mock issuer. Use New, then mount Handler.
type Server struct {
	issuerURL string
	personas  []string
	key       *rsa.PrivateKey

	mu    sync.Mutex
	codes map[string]pendingCode
}

// New builds a mock issuer that advertises itself at issuerURL.
//
// issuerURL must be exactly what clients configure as OIDC_ISSUER_URL: it is
// published as the iss claim, and go-oidc rejects a token whose iss differs
// from the discovery URL by so much as a trailing slash.
//
// personas seeds the interactive picker only. Any subject is accepted, so a
// test is free to sign in as a name that is not on this list.
func New(issuerURL string, personas []string) (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating mock idp key: %w", err)
	}

	return &Server{
		issuerURL: strings.TrimSuffix(issuerURL, "/"),
		personas:  personas,
		key:       key,
		codes:     map[string]pendingCode{},
	}, nil
}

// Handler returns the issuer's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)

	return mux
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuerURL,
		"authorization_endpoint":                s.issuerURL + "/authorize",
		"token_endpoint":                        s.issuerURL + "/token",
		"jwks_uri":                              s.issuerURL + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{algRS256},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"alg": algRS256,
		"use": "sig",
		"kid": signingKID,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// handleAuthorize is the "login page". A request that already names a subject
// via login_hint is redirected straight back; one that does not gets the
// persona picker, which is the same request with login_hint filled in.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	subject := q.Get("login_hint")
	if subject == "" {
		s.writePicker(w, r)
		return
	}

	if method := q.Get("code_challenge_method"); method != "" && method != "S256" {
		http.Error(w, "only S256 is supported", http.StatusBadRequest)
		return
	}

	code := randomString()
	s.mu.Lock()
	s.codes[code] = pendingCode{
		subject:     subject,
		nonce:       q.Get("nonce"),
		redirectURI: redirectURI,
		challenge:   q.Get("code_challenge"),
		expiresAt:   time.Now().Add(codeTTL),
	}
	s.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "unparseable redirect_uri", http.StatusBadRequest)
		return
	}
	rq := target.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	target.RawQuery = rq.Encode()

	// This is an issuer: redirecting to the client's redirect_uri is the whole
	// protocol. A dev-only mock has no client registry to check it against.
	http.Redirect(w, r, target.String(), http.StatusFound) //nolint:gosec // G710: a mock issuer redirects wherever the dev's client asks
}

// writePicker renders one link per persona, each being this same request with
// login_hint set. Keeping every other parameter intact is what makes the
// picker a step in the flow rather than a second entry point.
func (s *Server) writePicker(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=utf-8><title>mock idp</title>")
	b.WriteString("<h1>Sign in as</h1><ul>")
	for _, p := range s.personas {
		q := r.URL.Query()
		q.Set("login_hint", p)
		fmt.Fprintf(&b, `<li><a href="/authorize?%s">%s</a></li>`,
			q.Encode(), html.EscapeString(p))
	}
	b.WriteString("</ul>")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{errField: errBadReq})
		return
	}

	// Codes are single-use: redeeming one deletes it, so a replay fails even
	// inside the TTL.
	s.mu.Lock()
	pending, ok := s.codes[r.PostFormValue("code")]
	delete(s.codes, r.PostFormValue("code"))
	s.mu.Unlock()

	if !ok || time.Now().After(pending.expiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]string{errField: errBadGrant})
		return
	}
	if uri := r.PostFormValue("redirect_uri"); uri != "" && uri != pending.redirectURI {
		writeJSON(w, http.StatusBadRequest, map[string]string{errField: errBadGrant})
		return
	}
	// PKCE is enforced for real. A mock that rubber-stamped the verifier would
	// let a client ship with PKCE quietly broken.
	if pending.challenge != "" && s256(r.PostFormValue("code_verifier")) != pending.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{errField: errBadGrant})
		return
	}

	idToken, err := s.signIDToken(pending, clientIDFrom(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{errField: errServer})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": randomString(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

// signIDToken mints an RS256 ID token for the redeemed code.
func (s *Server) signIDToken(pending pendingCode, clientID string) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss":                s.issuerURL,
		"aud":                clientID,
		"sub":                pending.subject,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"email":              pending.subject + "@ocidex.test",
		"email_verified":     true,
		"name":               pending.subject,
		"preferred_username": pending.subject,
	}
	if pending.nonce != "" {
		claims["nonce"] = pending.nonce
	}

	header, err := b64JSON(map[string]any{"alg": algRS256, "typ": "JWT", "kid": signingKID})
	if err != nil {
		return "", err
	}
	payload, err := b64JSON(claims)
	if err != nil {
		return "", err
	}

	signing := header + "." + payload
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing id_token: %w", err)
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// clientIDFrom reads the client id from wherever the client put it.
//
// x/oauth2 picks between client_secret_basic and client_secret_post on its own,
// and the aud claim has to name the right client either way — a mock that only
// read the form body would mint tokens with an empty aud and fail verification
// for reasons that have nothing to do with the code under test.
func clientIDFrom(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok && id != "" {
		return id
	}

	return r.PostFormValue("client_id")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func b64JSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encoding jwt segment: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail in practice, and there is no caller here
		// with anything useful to do about it.
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}
