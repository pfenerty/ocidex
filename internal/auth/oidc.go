package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ProviderOIDCPrefix namespaces every generic-OIDC issuer key.
//
// Subjects are only unique within an issuer, so the stored provider must name
// which issuer minted them. The prefix keeps that namespace visibly separate
// from "github", whose subjects come from a different scheme entirely.
const ProviderOIDCPrefix = "oidc:"

// defaultOIDCScopes are what OCIDex asks every issuer for.
//
// openid is mandatory — without it there is no ID token and nothing to verify.
// profile and email are only for the display name and the advisory address;
// an issuer that refuses them still produces a usable account.
var defaultOIDCScopes = []string{oidc.ScopeOpenID, "profile", "email"}

// OIDCConfig is one configured issuer.
type OIDCConfig struct {
	// Name distinguishes this issuer from any other. It becomes part of the
	// provider key stored in user_identity and is therefore permanent:
	// renaming it orphans every account that signed in through it.
	Name string
	// IssuerURL is the discovery base — the URL that serves
	// /.well-known/openid-configuration. It must match the iss claim exactly.
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes overrides defaultOIDCScopes. openid is added if absent.
	Scopes []string
}

// OIDCProvider authenticates against any spec-compliant OIDC issuer:
// Google, Okta, Entra, Keycloak, Auth0 and GitLab are all this one type.
type OIDCProvider struct {
	name     string
	oauth2   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDCProvider performs discovery against the issuer and builds the provider.
//
// Discovery happens here, at startup, rather than lazily at first sign-in: a
// silently-degraded issuer would otherwise present a login button that 500s,
// and the operator would learn about the typo from a user instead of from the
// process refusing to start.
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("oidc: name is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc %q: client ID is required", cfg.Name)
	}

	issuer, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc %q: discovery against %s failed: %w", cfg.Name, cfg.IssuerURL, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = defaultOIDCScopes
	}
	scopes = withOpenID(scopes)

	return &OIDCProvider{
		name: ProviderOIDCPrefix + cfg.Name,
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     issuer.Endpoint(),
		},
		verifier: issuer.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// withOpenID returns scopes with the openid scope guaranteed present.
func withOpenID(scopes []string) []string {
	for _, s := range scopes {
		if s == oidc.ScopeOpenID {
			return scopes
		}
	}

	return append([]string{oidc.ScopeOpenID}, scopes...)
}

// Name returns the issuer key, "oidc:<name>".
func (p *OIDCProvider) Name() string { return p.name }

// AuthURL builds the issuer's authorize URL, binding this sign-in to the PKCE
// verifier. Only the S256 challenge travels to the issuer; the verifier itself
// stays in the state cookie, so an intercepted authorization code is useless
// without the browser that started the flow.
func (p *OIDCProvider) AuthURL(state, verifier string) string {
	return p.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))
}

// Exchange redeems the code and verifies the ID token that comes back.
func (p *OIDCProvider) Exchange(ctx context.Context, code, verifier string) (Identity, error) {
	// A missing verifier is refused here rather than left to the issuer. The
	// challenge was sent, so the exchange is required to answer it; an issuer
	// lax enough to accept the omission would downgrade the flow silently.
	if verifier == "" {
		return Identity{}, fmt.Errorf("oidc %s: missing PKCE verifier", p.name)
	}

	token, err := p.oauth2.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("oidc %s: exchanging code: %w", p.name, err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, fmt.Errorf("oidc %s: token response carried no id_token", p.name)
	}

	// The access token is not evidence of anything: it is opaque and was not
	// issued to us. The ID token's signature, issuer and audience are.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc %s: verifying id_token: %w", p.name, err)
	}

	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oidc %s: decoding claims: %w", p.name, err)
	}

	// sub is the only claim the spec guarantees is stable. Keying on email
	// instead would let an address change at the IdP hijack an account.
	subject := strings.TrimSpace(claims.Subject)
	if subject == "" {
		return Identity{}, fmt.Errorf("oidc %s: id_token carried no sub claim", p.name)
	}

	return Identity{
		Provider:    p.name,
		Subject:     subject,
		Email:       claims.Email,
		DisplayName: firstNonEmpty(claims.Name, claims.PreferredUsername, claims.Email),
	}, nil
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}

	return ""
}
