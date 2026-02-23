// Package config handles application configuration loaded from environment variables.
package config

import (
	"fmt"
	"log/slog"

	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration.
type Config struct {
	Port               int    `env:"PORT"            envDefault:"8080"`
	LogLevel           string `env:"LOG_LEVEL"       envDefault:"info"`
	Environment        string `env:"ENVIRONMENT"     envDefault:"development"`
	DatabaseURL        string `env:"DATABASE_URL,required"`
	CORSAllowedOrigins string `env:"CORS_ALLOWED_ORIGINS" envDefault:"*"`

	// Enrichment pipeline settings.
	EnrichmentEnabled   bool `env:"ENRICHMENT_ENABLED"   envDefault:"true"`
	EnrichmentWorkers   int  `env:"ENRICHMENT_WORKERS"   envDefault:"2"`
	EnrichmentQueueSize int  `env:"ENRICHMENT_QUEUE_SIZE" envDefault:"100"`

	// Audit logging.
	AuditLogEnabled bool `env:"AUDIT_LOG_ENABLED" envDefault:"true"`

	// NATS JetStream (optional outbound layer).
	NATSEnabled    bool   `env:"NATS_ENABLED"        envDefault:"false"`
	NATSURL        string `env:"NATS_URL"            envDefault:"nats://localhost:4222"`
	NATSStreamName string `env:"NATS_STREAM_NAME"    envDefault:"ocidex"`
	NATSEventTTL   int    `env:"NATS_EVENT_TTL_HOURS" envDefault:"24"`

	// Scanner (OCI registry auto-scan via Zot webhook).
	ScannerEnabled   bool   `env:"SCANNER_ENABLED"    envDefault:"false"`
	ScannerWorkers   int    `env:"SCANNER_WORKERS"    envDefault:"2"`
	ScannerQueueSize int    `env:"SCANNER_QUEUE_SIZE" envDefault:"50"`
	ZotRegistryAddr     string `env:"ZOT_REGISTRY_ADDR"     envDefault:"zot:5000"`
	ZotRegistryInsecure bool   `env:"ZOT_REGISTRY_INSECURE" envDefault:"false"`
	ZotWebhookSecret    string `env:"ZOT_WEBHOOK_SECRET"`
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
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
