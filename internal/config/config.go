// Package config handles application configuration loaded from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration.
type Config struct {
	Port               int    `env:"PORT"            envDefault:"8080"`
	LogLevel           string `env:"LOG_LEVEL"       envDefault:"info"`
	Environment        string `env:"ENVIRONMENT"     envDefault:"development"`
	DatabaseURL        string `env:"DATABASE_URL,required"`
	CORSAllowedOrigins string `env:"CORS_ALLOWED_ORIGINS" envDefault:""`

	// Enrichment pipeline settings.
	EnrichmentEnabled   bool `env:"ENRICHMENT_ENABLED"   envDefault:"true"`
	EnrichmentWorkers   int  `env:"ENRICHMENT_WORKERS"   envDefault:"2"`
	EnrichmentQueueSize int  `env:"ENRICHMENT_QUEUE_SIZE" envDefault:"100"`

	// Audit logging.
	AuditLogEnabled bool `env:"AUDIT_LOG_ENABLED" envDefault:"true"`

	// NATS JetStream — required. API publishes, workers consume.
	NATSURL            string `env:"NATS_URL"`
	NATSStreamName     string `env:"NATS_STREAM_NAME"     envDefault:"ocidex"`
	NATSEventTTL       int    `env:"NATS_EVENT_TTL_HOURS" envDefault:"24"`
	NATSStreamReplicas int    `env:"NATS_STREAM_REPLICAS" envDefault:"1"`

	// Database pool.
	DatabaseMaxConns int `env:"DATABASE_MAX_CONNECTIONS" envDefault:"10"`

	// GitHub OAuth.
	GitHubClientID     string `env:"GITHUB_CLIENT_ID"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET"`
	GitHubRedirectURL  string `env:"GITHUB_REDIRECT_URL" envDefault:"http://localhost:8080/auth/callback"`
	SessionSecret      string `env:"SESSION_SECRET"` //nolint:gosec
	SessionMaxAgeDays  int    `env:"SESSION_MAX_AGE_DAYS" envDefault:"7"`

	// Frontend URL — used as the post-OAuth redirect target and for CORS defaults.
	FrontendURL string `env:"FRONTEND_URL" envDefault:"http://localhost:3000"`

	// APIBaseURL — optional public base URL of the API, used to populate the OpenAPI servers block.
	APIBaseURL string `env:"API_BASE_URL" envDefault:""`

	// Scanner (OCI registry auto-scan via webhook).
	ScannerEnabled        bool `env:"SCANNER_ENABLED"          envDefault:"false"`
	ScannerMaxConcurrency int  `env:"SCANNER_MAX_CONCURRENCY"  envDefault:"10"`
	// ScannerPollInterval is the cadence at which each worker checks the DB
	// for queued scan_jobs rows, even when no NATS hint arrives. Keeps the
	// queue draining if NATS is unavailable.
	ScannerPollInterval time.Duration `env:"SCANNER_POLL_INTERVAL" envDefault:"30s"`
	// ScannerStuckThreshold is how long a 'running' scan_jobs row can go
	// without a last_attempt_at update before the sweep requeues it.
	ScannerStuckThreshold time.Duration `env:"SCANNER_STUCK_THRESHOLD" envDefault:"15m"`
	// ScannerMaxAttempts is the per-row retry budget. When attempts >= max,
	// FailOrRequeueByID transitions to 'failed' instead of 'queued'.
	ScannerMaxAttempts int `env:"SCANNER_MAX_ATTEMPTS" envDefault:"3"`

	// ScanDLQRetentionDays controls the TTL for scan_job_failures (DLQ) rows.
	// The scanner-worker purges anything older once per hour. 0 disables purging.
	ScanDLQRetentionDays int `env:"SCAN_DLQ_RETENTION_DAYS" envDefault:"30"`

	// Enrichment worker NATS concurrency.
	// EnrichmentMaxConcurrency controls goroutines per pod; EnrichmentMaxAckPending
	// is the JetStream global cap across all pods (defaults to maxConc*4 when zero).
	EnrichmentMaxConcurrency int `env:"ENRICHMENT_MAX_CONCURRENCY" envDefault:"50"`
	EnrichmentMaxAckPending  int `env:"ENRICHMENT_MAX_ACK_PENDING" envDefault:"0"`

	// RegistryPollerEnabled starts the background poller for poll-mode registries.
	RegistryPollerEnabled bool `env:"REGISTRY_POLLER_ENABLED" envDefault:"false"`
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.NATSURL == "" {
		return fmt.Errorf("NATS_URL is required")
	}
	return nil
}

// LogLevel returns the slog.Level corresponding to the configured log level string.
func (c *Config) SlogLevel() slog.Level {
	switch c.LogLevel {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
