package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/devidp"
)

// startMockIssuer runs an OIDC issuer buildIdentityProviders can discover, so
// the OIDC half of the configuration can be exercised without reaching the
// network.
func startMockIssuer(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(nil)
	idp, err := devidp.New(srv.URL, []string{"someone"})
	if err != nil {
		t.Fatalf("creating mock issuer: %v", err)
	}
	srv.Config.Handler = idp.Handler()
	t.Cleanup(srv.Close)

	return srv.URL
}

func providerNames(t *testing.T, cfg *config.Config) []string {
	t.Helper()

	providers, err := buildIdentityProviders(t.Context(), cfg)
	if err != nil {
		t.Fatalf("building providers: %v", err)
	}

	names := make([]string, 0, len(providers))
	for _, p := range providers {
		names = append(names, p.Name())
	}

	return names
}

// TestBuildIdentityProvidersAcceptsEitherProvider is the point of the change:
// GitHub is one way to sign in, not the way. An installation configured only
// against an OIDC issuer has to start.
func TestBuildIdentityProvidersAcceptsEitherProvider(t *testing.T) {
	issuer := startMockIssuer(t)

	tests := []struct {
		name string
		cfg  *config.Config
		want []string
	}{
		{
			name: "github only",
			cfg: &config.Config{
				SessionSecret:      "secret",
				GitHubClientID:     "id",
				GitHubClientSecret: "shh",
			},
			want: []string{"github"},
		},
		{
			name: "oidc only",
			cfg: &config.Config{
				SessionSecret: "secret",
				OIDCIssuerURL: issuer,
				OIDCClientID:  "ocidex-dev",
				OIDCName:      "mock",
			},
			want: []string{"oidc:mock"},
		},
		{
			name: "both",
			cfg: &config.Config{
				SessionSecret:      "secret",
				GitHubClientID:     "id",
				GitHubClientSecret: "shh",
				OIDCIssuerURL:      issuer,
				OIDCClientID:       "ocidex-dev",
				OIDCName:           "mock",
			},
			want: []string{"github", "oidc:mock"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(providerNames(t, tt.cfg), tt.want)
		})
	}
}

// TestBuildIdentityProvidersRejectsUnusableConfig covers the three ways a
// configuration cannot produce a working login, each of which has to stop the
// process rather than surface as a broken sign-in page.
func TestBuildIdentityProvidersRejectsUnusableConfig(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		wantHint string
	}{
		{
			name: "no session secret",
			cfg: &config.Config{
				GitHubClientID:     "id",
				GitHubClientSecret: "shh",
			},
			wantHint: "SESSION_SECRET",
		},
		{
			name:     "no provider at all",
			cfg:      &config.Config{SessionSecret: "secret"},
			wantHint: "no identity provider configured",
		},
		{
			// Half a pair is a typo, not a decision to turn GitHub off.
			name: "github client id without secret",
			cfg: &config.Config{
				SessionSecret:  "secret",
				GitHubClientID: "id",
			},
			wantHint: "must be set together",
		},
		{
			name: "github secret without client id",
			cfg: &config.Config{
				SessionSecret:      "secret",
				GitHubClientSecret: "shh",
			},
			wantHint: "must be set together",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			_, err := buildIdentityProviders(t.Context(), tt.cfg)
			is.True(err != nil)
			is.True(strings.Contains(err.Error(), tt.wantHint))
		})
	}
}
