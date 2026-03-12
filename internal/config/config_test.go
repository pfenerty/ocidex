package config_test

import (
	"log/slog"
	"os"
	"testing"

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
			name: "defaults applied",
			env: map[string]string{
				"DATABASE_URL": "postgres://localhost/test",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.Port, 8080)
				is.Equal(cfg.LogLevel, "info")
				is.Equal(cfg.Environment, "development")
				is.Equal(cfg.DatabaseURL, "postgres://localhost/test")
				is.Equal(cfg.DatabaseMaxConns, 10)
				is.Equal(cfg.NATSStreamReplicas, 1)
				is.Equal(cfg.EnrichmentNATSMode, false)
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
				"ENRICHMENT_NATS_MODE":     "true",
			},
			check: func(is *is.I, cfg *config.Config) {
				is.Equal(cfg.Port, 9090)
				is.Equal(cfg.LogLevel, "debug")
				is.Equal(cfg.Environment, "production")
				is.Equal(cfg.DatabaseMaxConns, 3)
				is.Equal(cfg.NATSStreamReplicas, 3)
				is.Equal(cfg.EnrichmentNATSMode, true)
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
