package config_test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/pfenerty/ocidex/internal/config"
)

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
			name: "overrides",
			env: map[string]string{
				"PORT":                     "9090",
				"LOG_LEVEL":                "debug",
				"ENVIRONMENT":              "production",
				"DATABASE_URL":             "postgres://prod/ocidex",
				"DATABASE_MAX_CONNECTIONS": "3",
				"NATS_STREAM_REPLICAS":     "3",
				"NATS_URL":                 "nats://nats:4222",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.Port, 9090)
				is.Equal(cfg.LogLevel, "debug")
				is.Equal(cfg.Environment, "production")
				is.Equal(cfg.DatabaseMaxConns, 3)
				is.Equal(cfg.NATSStreamReplicas, 3)
				is.Equal(cfg.NATSURL, "nats://nats:4222")
			},
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
			for _, k := range []string{"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "SESSION_SECRET"} {
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
