// Package config handles application configuration loaded from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
)

// parseSlogLevel maps a log-level string to its slog.Level (default Info).
func parseSlogLevel(level string) slog.Level {
	switch level {
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

	// Enrichment worker outbox-pattern settings (mirrors the scanner equivalents).
	EnrichmentMaxConcurrency int           `env:"ENRICHMENT_MAX_CONCURRENCY"  envDefault:"10"`
	EnrichmentPollInterval   time.Duration `env:"ENRICHMENT_POLL_INTERVAL"    envDefault:"30s"`
	EnrichmentStuckThreshold time.Duration `env:"ENRICHMENT_STUCK_THRESHOLD"  envDefault:"10m"`
	EnrichmentMaxAttempts    int           `env:"ENRICHMENT_MAX_ATTEMPTS"     envDefault:"3"`

	// RegistryPollerEnabled starts the background poller for poll-mode registries.
	RegistryPollerEnabled bool `env:"REGISTRY_POLLER_ENABLED" envDefault:"false"`

	// Ingest-time vuln lookup — queries OSV for purls from newly ingested SBOMs
	// that are not yet in package_vulnerability. Shares env var names with VulnWorkerConfig.
	IngestVulnLookupEnabled bool          `env:"INGEST_VULN_LOOKUP_ENABLED" envDefault:"true"`
	OSVBaseURL              string        `env:"OSV_BASE_URL"               envDefault:"https://api.osv.dev"`
	OSVTimeout              time.Duration `env:"OSV_TIMEOUT"                envDefault:"30s"`
	OSVBatchSize            int           `env:"OSV_BATCH_SIZE"             envDefault:"1000"`
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

// VulnWorkerConfig holds configuration for the vulnerability refresh worker
// (cmd/vuln-worker). It talks only to Postgres and OSV.dev — no NATS — so it has
// its own loader rather than the NATS-requiring Config.
type VulnWorkerConfig struct {
	LogLevel         string `env:"LOG_LEVEL"    envDefault:"info"`
	Environment      string `env:"ENVIRONMENT"  envDefault:"development"`
	DatabaseURL      string `env:"DATABASE_URL,required"`
	DatabaseMaxConns int    `env:"DATABASE_MAX_CONNECTIONS" envDefault:"5"`

	// OSVBaseURL is the OSV.dev API base URL.
	OSVBaseURL string `env:"OSV_BASE_URL" envDefault:"https://api.osv.dev"`
	// OSVTimeout bounds a single OSV HTTP request.
	OSVTimeout time.Duration `env:"OSV_TIMEOUT" envDefault:"30s"`
	// OSVBatchSize is the querybatch chunk size (OSV allows up to 1000).
	OSVBatchSize int `env:"OSV_BATCH_SIZE" envDefault:"1000"`

	// RefreshEnabled gates the scheduled refresh loop.
	RefreshEnabled bool `env:"VULN_REFRESH_ENABLED" envDefault:"true"`
	// RefreshInterval is the minimum time between full refreshes.
	RefreshInterval time.Duration `env:"VULN_REFRESH_INTERVAL" envDefault:"6h"`

	// IncrementalRefreshEnabled enables per-ecosystem modified_id.csv checks so
	// only changed ecosystems are re-queried each cycle. Set to false to revert
	// to a full-scan on every cycle.
	IncrementalRefreshEnabled bool `env:"VULN_INCREMENTAL_ENABLED" envDefault:"true"`
	// OSVBucketBaseURL is the base URL for OSV's per-ecosystem modified_id.csv files.
	OSVBucketBaseURL string `env:"OSV_BUCKET_BASE_URL" envDefault:"https://storage.googleapis.com/osv-vulnerabilities"`
}

// LoadVulnWorker reads vuln-worker configuration from environment variables.
func LoadVulnWorker() (*VulnWorkerConfig, error) {
	cfg := &VulnWorkerConfig{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

// SlogLevel returns the slog.Level for a VulnWorkerConfig.
func (c *VulnWorkerConfig) SlogLevel() slog.Level {
	return parseSlogLevel(c.LogLevel)
}

// OperatorConfig holds the subset of configuration needed by the K8s operator.
// The operator communicates only with the OCIDex API — it does not require a
// database connection or NATS.
type OperatorConfig struct {
	LogLevel    string `env:"LOG_LEVEL"    envDefault:"info"`
	Environment string `env:"ENVIRONMENT"  envDefault:"development"`
}

// LoadOperator reads operator-specific configuration from environment variables.
func LoadOperator() (*OperatorConfig, error) {
	cfg := &OperatorConfig{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

// SlogLevel returns the slog.Level for an OperatorConfig.
func (c *OperatorConfig) SlogLevel() slog.Level {
	return parseSlogLevel(c.LogLevel)
}

func (c *Config) validate() error {
	if c.NATSURL == "" {
		return fmt.Errorf("NATS_URL is required")
	}
	return nil
}

// LogLevel returns the slog.Level corresponding to the configured log level string.
func (c *Config) SlogLevel() slog.Level {
	return parseSlogLevel(c.LogLevel)
}
