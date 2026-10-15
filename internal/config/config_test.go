package config_test

import (
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/config"
)

// testKey is a valid base64 AES-256 key for DATA_ENCRYPTION_KEYS.
const testKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		check   func(*is.I, *config.Config)
	}{
		{
			name:    "missing required DATABASE_URL",
			env:     map[string]string{},
			wantErr: true,
		},
		{
			name: "missing required NATS_URL",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
			},
			wantErr: true,
		},
		{
			name: "defaults applied",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.Port, 8080)
				is.Equal(cfg.LogLevel, "info")
				is.Equal(cfg.Environment, "development")
				is.Equal(cfg.DatabaseURL, "postgres://localhost/test")
				is.Equal(cfg.DatabaseMaxConns, 10)
				is.Equal(cfg.NATSStreamReplicas, 1)
				is.Equal(cfg.NATSURL, "nats://localhost:4222")
			},
		},
		{
			name: "session cookie SameSite defaults to lax",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.SessionCookieSameSite, config.SameSiteLax)
			},
		},
		{
			name: "session cookie SameSite is case-insensitive",
			env: map[string]string{
				"DATABASE_URL":            "postgres://localhost/test",
				"NATS_URL":                "nats://localhost:4222",
				"SESSION_COOKIE_SAMESITE": "Strict",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.SessionCookieSameSite, config.SameSiteStrict)
			},
		},
		{
			// SameSite=None without Secure is dropped by browsers, and Secure
			// is only set in production.
			name: "session cookie SameSite none outside production is rejected",
			env: map[string]string{
				"DATABASE_URL":            "postgres://localhost/test",
				"NATS_URL":                "nats://localhost:4222",
				"SESSION_COOKIE_SAMESITE": "none",
			},
			wantErr: true,
		},
		{
			name: "session cookie SameSite unknown value is rejected",
			env: map[string]string{
				"DATABASE_URL":            "postgres://localhost/test",
				"NATS_URL":                "nats://localhost:4222",
				"SESSION_COOKIE_SAMESITE": "relaxed",
			},
			wantErr: true,
		},
		{
			name: "CORS origin * in production",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"ENVIRONMENT":                "production",
				"CORS_ALLOWED_ORIGINS":       "*",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			wantErr: true,
		},
		{
			name: "CORS origin * in development",
			env: map[string]string{
				"DATABASE_URL":         "postgres://localhost/test",
				"NATS_URL":             "nats://localhost:4222",
				"ENVIRONMENT":          "development",
				"CORS_ALLOWED_ORIGINS": "*",
			},
			wantErr: false,
		},
		{
			name: "CORS origin https://a.example in production",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"ENVIRONMENT":                "production",
				"CORS_ALLOWED_ORIGINS":       "https://a.example",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			wantErr: false,
		},
		{
			name: "CORS origin https://a.example in development",
			env: map[string]string{
				"DATABASE_URL":         "postgres://localhost/test",
				"NATS_URL":             "nats://localhost:4222",
				"ENVIRONMENT":          "development",
				"CORS_ALLOWED_ORIGINS": "https://a.example",
			},
			wantErr: false,
		},
		{
			name: "CORS origin https://a.example:8443, http://b.example in production",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"ENVIRONMENT":                "production",
				"CORS_ALLOWED_ORIGINS":       "https://a.example:8443, http://b.example",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			wantErr: false,
		},
		{
			name: "CORS origin https://a.example:8443, http://b.example in development",
			env: map[string]string{
				"DATABASE_URL":         "postgres://localhost/test",
				"NATS_URL":             "nats://localhost:4222",
				"ENVIRONMENT":          "development",
				"CORS_ALLOWED_ORIGINS": "https://a.example:8443, http://b.example",
			},
			wantErr: false,
		},
		{
			name: "CORS origin https://a.example/path in production",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"ENVIRONMENT":                "production",
				"CORS_ALLOWED_ORIGINS":       "https://a.example/path",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			wantErr: true,
		},
		{
			name: "CORS origin https://a.example/path in development",
			env: map[string]string{
				"DATABASE_URL":         "postgres://localhost/test",
				"NATS_URL":             "nats://localhost:4222",
				"ENVIRONMENT":          "development",
				"CORS_ALLOWED_ORIGINS": "https://a.example/path",
			},
			wantErr: false,
		},
		{
			name: "CORS origin https://a.example/ in production",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"ENVIRONMENT":                "production",
				"CORS_ALLOWED_ORIGINS":       "https://a.example/",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			wantErr: true,
		},
		{
			name: "CORS origin https://a.example/ in development",
			env: map[string]string{
				"DATABASE_URL":         "postgres://localhost/test",
				"NATS_URL":             "nats://localhost:4222",
				"ENVIRONMENT":          "development",
				"CORS_ALLOWED_ORIGINS": "https://a.example/",
			},
			wantErr: false,
		},
		{
			name: "CORS origin a.example in production",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"ENVIRONMENT":                "production",
				"CORS_ALLOWED_ORIGINS":       "a.example",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			wantErr: true,
		},
		{
			name: "CORS origin a.example in development",
			env: map[string]string{
				"DATABASE_URL":         "postgres://localhost/test",
				"NATS_URL":             "nats://localhost:4222",
				"ENVIRONMENT":          "development",
				"CORS_ALLOWED_ORIGINS": "a.example",
			},
			wantErr: false,
		},
		{
			name: "auth rate limit defaults to 30 and trusts no proxy",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.AuthRateLimit, 30)
				is.Equal(len(cfg.TrustedProxies), 0)
			},
		},
		{
			name: "TRUSTED_PROXY_CIDRS parses CIDRs and bare addresses",
			env: map[string]string{
				"DATABASE_URL":        "postgres://localhost/test",
				"NATS_URL":            "nats://localhost:4222",
				"TRUSTED_PROXY_CIDRS": "10.0.0.0/8, 192.0.2.1",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(len(cfg.TrustedProxies), 2)
				is.Equal(cfg.TrustedProxies[1].String(), "192.0.2.1/32")
			},
		},
		{
			name: "malformed TRUSTED_PROXY_CIDRS is rejected",
			env: map[string]string{
				"DATABASE_URL":        "postgres://localhost/test",
				"NATS_URL":            "nats://localhost:4222",
				"TRUSTED_PROXY_CIDRS": "10.0.0.0/33",
			},
			wantErr: true,
		},
		{
			name: "negative AUTH_RATE_LIMIT is rejected",
			env: map[string]string{
				"DATABASE_URL":    "postgres://localhost/test",
				"NATS_URL":        "nats://localhost:4222",
				"AUTH_RATE_LIMIT": "-1",
			},
			wantErr: true,
		},
		{
			name: "OIDC off by default",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.OIDCIssuerURL, "")
				is.Equal(cfg.OIDCName, "oidc")
				is.Equal(cfg.OIDCRedirectURL, "http://localhost:8080/auth/callback")
			},
		},
		{
			// Half-configured OIDC is worse than none: the login button would
			// exist and fail. Reject it at load rather than at first click.
			name: "OIDC issuer without client ID is rejected",
			env: map[string]string{
				"DATABASE_URL":    "postgres://localhost/test",
				"NATS_URL":        "nats://localhost:4222",
				"OIDC_ISSUER_URL": "https://issuer.example.com",
			},
			wantErr: true,
		},
		{
			name: "OIDC client ID without issuer is rejected",
			env: map[string]string{
				"DATABASE_URL":   "postgres://localhost/test",
				"NATS_URL":       "nats://localhost:4222",
				"OIDC_CLIENT_ID": "abc",
			},
			wantErr: true,
		},
		{
			name: "OIDC scopes parse as a comma-separated list",
			env: map[string]string{
				"DATABASE_URL":    "postgres://localhost/test",
				"NATS_URL":        "nats://localhost:4222",
				"OIDC_ISSUER_URL": "https://issuer.example.com",
				"OIDC_CLIENT_ID":  "abc",
				"OIDC_NAME":       "keycloak",
				"OIDC_SCOPES":     "openid,profile,email,groups",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.OIDCName, "keycloak")
				is.Equal(cfg.OIDCScopes, []string{"openid", "profile", "email", "groups"})
			},
		},
		{
			// Regression guard for ocidex-mf3: the scanner/enrichment workers
			// share config.Load() but never authenticate browser sessions, so
			// GITHUB_*/SESSION_SECRET must remain optional. Load() must succeed
			// with only DATABASE_URL/NATS_URL set and leave the OAuth fields empty.
			name: "OAuth/session vars not required (workers, ocidex-mf3)",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.GitHubClientID, "")
				is.Equal(cfg.GitHubClientSecret, "")
				is.Equal(cfg.SessionSecret, "")
			},
		},
		{
			name: "BOOTSTRAP_ADMINS parses github and oidc entries",
			env: map[string]string{
				"DATABASE_URL":     "postgres://localhost/test",
				"NATS_URL":         "nats://localhost:4222",
				"BOOTSTRAP_ADMINS": " github:42 , oidc:corp:a:b|c,",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.BootstrapAdmins, []config.IdentityRef{
					{Provider: "github", Subject: "42"},
					{Provider: "oidc:corp", Subject: "a:b|c"},
				})
			},
		},
		{
			name: "BOOTSTRAP_ADMINS unset is empty",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(len(cfg.BootstrapAdmins), 0)
			},
		},
		{
			name: "BOOTSTRAP_ADMINS bare subject is rejected",
			env: map[string]string{
				"DATABASE_URL":     "postgres://localhost/test",
				"NATS_URL":         "nats://localhost:4222",
				"BOOTSTRAP_ADMINS": "16961380",
			},
			wantErr: true,
		},
		{
			name: "BOOTSTRAP_ADMINS unknown provider is rejected",
			env: map[string]string{
				"DATABASE_URL":     "postgres://localhost/test",
				"NATS_URL":         "nats://localhost:4222",
				"BOOTSTRAP_ADMINS": "gitlab:1",
			},
			wantErr: true,
		},
		{
			name: "BOOTSTRAP_ADMINS oidc without name is rejected",
			env: map[string]string{
				"DATABASE_URL":     "postgres://localhost/test",
				"NATS_URL":         "nats://localhost:4222",
				"BOOTSTRAP_ADMINS": "oidc:abc",
			},
			wantErr: true,
		},
		{
			name: "BOOTSTRAP_ADMINS empty subject is rejected",
			env: map[string]string{
				"DATABASE_URL":     "postgres://localhost/test",
				"NATS_URL":         "nats://localhost:4222",
				"BOOTSTRAP_ADMINS": "github:",
			},
			wantErr: true,
		},
		{
			name: "installation policy defaults stay open",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.SignupMode, config.SignupOpen)
				is.Equal(cfg.RestrictNamespaceCreation, false)
			},
		},
		{
			name: "installation policy closed",
			env: map[string]string{
				"DATABASE_URL":            "postgres://localhost/test",
				"NATS_URL":                "nats://localhost:4222",
				"SIGNUP_MODE":             "existing",
				"SELF_SERVICE_NAMESPACES": "false",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.SignupMode, config.SignupExisting)
				is.Equal(cfg.RestrictNamespaceCreation, true)
			},
		},
		{
			name: "unknown SIGNUP_MODE is rejected",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
				"SIGNUP_MODE":  "closed",
			},
			wantErr: true,
		},
		{
			name: "non-boolean SELF_SERVICE_NAMESPACES is rejected",
			env: map[string]string{
				"DATABASE_URL":            "postgres://localhost/test",
				"NATS_URL":                "nats://localhost:4222",
				"SELF_SERVICE_NAMESPACES": "maybe",
			},
			wantErr: true,
		},
		{
			name: "egress defaults deny private",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.EgressPolicy.AllowPrivate, false)
				is.Equal(len(cfg.EgressPolicy.AllowCIDRs), 0)
				is.True(cfg.EgressPolicy.Check(netip.MustParseAddr("10.0.0.1")) != nil)
			},
		},
		{
			name: "egress settings parse",
			env: map[string]string{
				"DATABASE_URL":         "postgres://localhost/test",
				"NATS_URL":             "nats://localhost:4222",
				"EGRESS_ALLOW_PRIVATE": "true",
				"EGRESS_ALLOW_CIDRS":   "127.0.0.0/8, 10.0.0.5",
				"EGRESS_DENY_CIDRS":    "10.96.0.0/12",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.EgressPolicy.AllowPrivate, true)
				is.Equal(cfg.EgressPolicy.AllowCIDRs, []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.5/32"),
				})
				is.Equal(cfg.EgressPolicy.DenyCIDRs, []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12")})
			},
		},
		{
			name: "bad EGRESS_ALLOW_CIDRS is rejected",
			env: map[string]string{
				"DATABASE_URL":       "postgres://localhost/test",
				"NATS_URL":           "nats://localhost:4222",
				"EGRESS_ALLOW_CIDRS": "10.0.0.0/33",
			},
			wantErr: true,
		},
		{
			name: "bad EGRESS_DENY_CIDRS is rejected",
			env: map[string]string{
				"DATABASE_URL":      "postgres://localhost/test",
				"NATS_URL":          "nats://localhost:4222",
				"EGRESS_DENY_CIDRS": "nope",
			},
			wantErr: true,
		},
		{
			name: "overrides",
			env: map[string]string{
				"PORT":                       "9090",
				"LOG_LEVEL":                  "debug",
				"ENVIRONMENT":                "production",
				"DATABASE_URL":               "postgres://prod/ocidex",
				"DATABASE_MAX_CONNECTIONS":   "3",
				"NATS_STREAM_REPLICAS":       "3",
				"NATS_URL":                   "nats://nats:4222",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.Port, 9090)
				is.Equal(cfg.LogLevel, "debug")
				is.Equal(cfg.Environment, "production")
				is.Equal(cfg.DatabaseMaxConns, 3)
				is.Equal(cfg.NATSStreamReplicas, 3)
				is.Equal(cfg.NATSURL, "nats://nats:4222")
				is.Equal(cfg.SecretBox.ActiveKey(), "k1")
			},
		},
		{
			name: "no encryption key outside production leaves SecretBox nil",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.True(cfg.SecretBox == nil)
			},
		},
		{
			name: "production without an encryption key is rejected",
			env: map[string]string{
				"ENVIRONMENT":  "production",
				"DATABASE_URL": "postgres://localhost/test",
				"NATS_URL":     "nats://localhost:4222",
			},
			wantErr: true,
		},
		{
			name: "malformed DATA_ENCRYPTION_KEYS is rejected",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"DATA_ENCRYPTION_KEYS":       "k1:tooshort",
				"DATA_ENCRYPTION_ACTIVE_KEY": "k1",
			},
			wantErr: true,
		},
		{
			name: "active key not in DATA_ENCRYPTION_KEYS is rejected",
			env: map[string]string{
				"DATABASE_URL":               "postgres://localhost/test",
				"NATS_URL":                   "nats://localhost:4222",
				"DATA_ENCRYPTION_KEYS":       "k1:" + testKey,
				"DATA_ENCRYPTION_ACTIVE_KEY": "k2",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			// Save and unset DATABASE_URL so the "missing required" test works
			// even when the var is set in the outer environment.
			// t.Setenv saves the original value and restores it in cleanup;
			// os.Unsetenv then actually removes it for the duration of the test.
			t.Setenv("DATABASE_URL", "")
			os.Unsetenv("DATABASE_URL") //nolint:errcheck
			t.Setenv("NATS_URL", "")
			os.Unsetenv("NATS_URL") //nolint:errcheck

			// Clear OAuth vars — no longer required by config.Load().
			for _, k := range []string{"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "SESSION_SECRET", "BOOTSTRAP_ADMINS", "EGRESS_ALLOW_PRIVATE", "EGRESS_ALLOW_CIDRS", "EGRESS_DENY_CIDRS", "SIGNUP_MODE", "SELF_SERVICE_NAMESPACES", "DATA_ENCRYPTION_KEYS", "DATA_ENCRYPTION_ACTIVE_KEY", "ENVIRONMENT"} {
				t.Setenv(k, "")
				os.Unsetenv(k) //nolint:errcheck
			}

			// Set env vars for this test.
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := config.Load()

			if tt.wantErr {
				is.True(err != nil)
				return
			}
			is.NoErr(err)
			if tt.check != nil {
				tt.check(is, cfg)
			}
		})
	}
}

// TestLoadOperator covers the leader-election timings added for ocidex-vh6. The
// defaults must stay wider than controller-runtime's 15s/10s/2s, because the
// per-request API-server timeout is derived as RenewDeadline/2 and a 5s budget
// is not enough for a loaded control plane.
func TestLoadOperator(t *testing.T) {
	leaderElectionVars := []string{
		"LEADER_ELECTION_LEASE_DURATION",
		"LEADER_ELECTION_RENEW_DEADLINE",
		"LEADER_ELECTION_RETRY_PERIOD",
	}

	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		check   func(*is.I, *config.OperatorConfig)
	}{
		{
			name: "defaults applied",
			env:  map[string]string{},
			check: func(is *is.I, cfg *config.OperatorConfig) {
				is.Equal(cfg.LogLevel, "info")
				is.Equal(cfg.Environment, "development")
				is.Equal(cfg.ServerURL, "http://ocidex:8080")
				is.Equal(cfg.APIKey, "ocidex_test")
				is.Equal(cfg.OperatorNamespace, "ocidex-system")
				is.Equal(cfg.LeaderElectionLeaseDuration, 60*time.Second)
				is.Equal(cfg.LeaderElectionRenewDeadline, 40*time.Second)
				is.Equal(cfg.LeaderElectionRetryPeriod, 10*time.Second)
			},
		},
		{
			name: "overrides",
			env: map[string]string{
				"LEADER_ELECTION_LEASE_DURATION": "30s",
				"LEADER_ELECTION_RENEW_DEADLINE": "25s",
				"LEADER_ELECTION_RETRY_PERIOD":   "5s",
			},
			check: func(is *is.I, cfg *config.OperatorConfig) {
				is.Equal(cfg.LeaderElectionLeaseDuration, 30*time.Second)
				is.Equal(cfg.LeaderElectionRenewDeadline, 25*time.Second)
				is.Equal(cfg.LeaderElectionRetryPeriod, 5*time.Second)
			},
		},
		{
			name: "renew deadline must be below lease duration",
			env: map[string]string{
				"LEADER_ELECTION_LEASE_DURATION": "30s",
				"LEADER_ELECTION_RENEW_DEADLINE": "30s",
				"LEADER_ELECTION_RETRY_PERIOD":   "5s",
			},
			wantErr: true,
		},
		{
			// client-go panics unless RenewDeadline > RetryPeriod*JitterFactor(1.2).
			name: "renew deadline must exceed retry period times jitter factor",
			env: map[string]string{
				"LEADER_ELECTION_LEASE_DURATION": "60s",
				"LEADER_ELECTION_RENEW_DEADLINE": "12s",
				"LEADER_ELECTION_RETRY_PERIOD":   "10s",
			},
			wantErr: true,
		},
		{
			name: "zero durations rejected",
			env: map[string]string{
				"LEADER_ELECTION_RETRY_PERIOD": "0s",
			},
			wantErr: true,
		},
		{
			// The deployed configuration. A single name must keep parsing as a
			// one-element list, or making WATCH_NAMESPACE comma-separated would
			// silently change the watch scope of every existing install.
			name: "single namespace",
			env:  map[string]string{"WATCH_NAMESPACE": "ocidex-dev"},
			check: func(is *is.I, cfg *config.OperatorConfig) {
				is.Equal(cfg.WatchNamespaces, []string{"ocidex-dev"})
			},
		},
		{
			name: "multiple namespaces",
			env:  map[string]string{"WATCH_NAMESPACE": "ocidex-dev,ocidex"},
			check: func(is *is.I, cfg *config.OperatorConfig) {
				is.Equal(cfg.WatchNamespaces, []string{"ocidex-dev", "ocidex"})
			},
		},
		{
			name: "surrounding whitespace and empty entries dropped",
			env:  map[string]string{"WATCH_NAMESPACE": " ocidex-dev , , ocidex "},
			check: func(is *is.I, cfg *config.OperatorConfig) {
				is.Equal(cfg.WatchNamespaces, []string{"ocidex-dev", "ocidex"})
			},
		},
		{
			name:    "empty watch namespace rejected",
			env:     map[string]string{"WATCH_NAMESPACE": ""},
			wantErr: true,
		},
		{
			// Would otherwise normalise to an empty list, and an empty cache key
			// widens the watch to every namespace instead of narrowing it.
			name:    "separators only rejected",
			env:     map[string]string{"WATCH_NAMESPACE": " , "},
			wantErr: true,
		},
		{
			// An unset secretKeyRef surfaces as an empty string rather than an
			// absent var, so these must fail on the value, not on presence.
			name:    "missing server url rejected",
			env:     map[string]string{"OCIDEX_SERVER": ""},
			wantErr: true,
		},
		{
			name:    "missing api key rejected",
			env:     map[string]string{"OCIDEX_API_KEY": ""},
			wantErr: true,
		},
		{
			name:    "missing operator namespace rejected",
			env:     map[string]string{"OPERATOR_NAMESPACE": ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			// Clear inherited values so defaults are exercised faithfully.
			for _, k := range append([]string{"LOG_LEVEL", "ENVIRONMENT"}, leaderElectionVars...) {
				t.Setenv(k, "")
				os.Unsetenv(k) //nolint:errcheck
			}
			// These are all required, so give every case a valid value by
			// default — otherwise unrelated cases would fail for the wrong
			// reason. Cases exercising a specific var override it.
			t.Setenv("WATCH_NAMESPACE", "ocidex-dev")
			t.Setenv("OCIDEX_SERVER", "http://ocidex:8080")
			t.Setenv("OCIDEX_API_KEY", "ocidex_test")
			t.Setenv("OPERATOR_NAMESPACE", "ocidex-system")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := config.LoadOperator()

			if tt.wantErr {
				is.True(err != nil)
				return
			}
			is.NoErr(err)
			if tt.check != nil {
				tt.check(is, cfg)
			}
		})
	}
}

func TestLoadK8sAgent(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
		check   func(*is.I, *config.K8sAgentConfig)
	}{
		{
			name: "defaults applied",
			env:  map[string]string{},
			check: func(is *is.I, cfg *config.K8sAgentConfig) {
				is.Equal(cfg.LogLevel, "info")
				is.Equal(cfg.Environment, "development")
				is.Equal(cfg.ClusterID, "cluster-uuid")
				is.Equal(cfg.ReportInterval, 5*time.Minute)
				is.Equal(cfg.HealthAddr, ":9090")
				// Unlike the operator's WATCH_NAMESPACE, an empty list is the valid
				// and expected default: it means report every namespace.
				is.Equal(cfg.Namespaces, []string{})
			},
		},
		{
			name: "namespace allowlist",
			env:  map[string]string{"OCIDEX_NAMESPACES": "default,kube-system"},
			check: func(is *is.I, cfg *config.K8sAgentConfig) {
				is.Equal(cfg.Namespaces, []string{"default", "kube-system"})
			},
		},
		{
			name: "whitespace and empty entries dropped",
			env:  map[string]string{"OCIDEX_NAMESPACES": " default , , kube-system "},
			check: func(is *is.I, cfg *config.K8sAgentConfig) {
				is.Equal(cfg.Namespaces, []string{"default", "kube-system"})
			},
		},
		{
			// Separators only must widen to every namespace rather than narrow to
			// nothing — the inverse of the operator's rule, because here an empty
			// list is meaningful.
			name: "separators only means all namespaces",
			env:  map[string]string{"OCIDEX_NAMESPACES": " , "},
			check: func(is *is.I, cfg *config.K8sAgentConfig) {
				is.Equal(cfg.Namespaces, []string{})
			},
		},
		{
			name: "interval override",
			env:  map[string]string{"OCIDEX_REPORT_INTERVAL": "30s"},
			check: func(is *is.I, cfg *config.K8sAgentConfig) {
				is.Equal(cfg.ReportInterval, 30*time.Second)
			},
		},
		{
			// A zero interval would make the ticker panic at construction.
			name:    "zero interval rejected",
			env:     map[string]string{"OCIDEX_REPORT_INTERVAL": "0s"},
			wantErr: true,
		},
		{
			// Same reason as the operator: an unset secretKeyRef surfaces as an
			// empty string, so these must fail on the value, not on presence.
			name:    "missing server url rejected",
			env:     map[string]string{"OCIDEX_SERVER": ""},
			wantErr: true,
		},
		{
			name:    "missing api key rejected",
			env:     map[string]string{"OCIDEX_API_KEY": ""},
			wantErr: true,
		},
		{
			// Without it the agent would have no cluster to replace the inventory
			// of, and a defaulted one could replace the wrong cluster's.
			name:    "missing cluster id rejected",
			env:     map[string]string{"OCIDEX_CLUSTER_ID": ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			for _, k := range []string{"LOG_LEVEL", "ENVIRONMENT", "OCIDEX_NAMESPACES", "OCIDEX_REPORT_INTERVAL", "HEALTH_ADDR"} {
				t.Setenv(k, "")
				os.Unsetenv(k) //nolint:errcheck
			}
			t.Setenv("OCIDEX_SERVER", "http://ocidex:8080")
			t.Setenv("OCIDEX_API_KEY", "ocidex_test")
			t.Setenv("OCIDEX_CLUSTER_ID", "cluster-uuid")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := config.LoadK8sAgent()

			if tt.wantErr {
				is.True(err != nil)
				return
			}
			is.NoErr(err)
			if tt.check != nil {
				tt.check(is, cfg)
			}
		})
	}
}

func TestSlogLevel(t *testing.T) {
	tests := []struct {
		level string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			is := is.New(t)
			cfg := &config.Config{LogLevel: tt.level}
			is.Equal(cfg.SlogLevel(), tt.want)
		})
	}
}
