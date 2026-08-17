// Package config handles application configuration loaded from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"strings"
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

	// ProvenanceRecheckInterval is how old a SBOM's last successful provenance
	// check must be before it's requeued for re-verification (drift detection:
	// trust config changes, registry deletions).
	ProvenanceRecheckInterval time.Duration `env:"PROVENANCE_RECHECK_INTERVAL" envDefault:"24h"`
	// ProvenanceReverifierEnabled gates the provenance recheck sweep. Defaults
	// to true since it already runs unconditionally today; set to false to
	// disable (e.g. in a test/staging environment without registry access).
	ProvenanceReverifierEnabled bool `env:"PROVENANCE_REVERIFIER_ENABLED" envDefault:"true"`

	// Ingest-time vuln lookup — queries OSV for purls from newly ingested SBOMs
	// that are not yet in package_vulnerability. Shares env var names with VulnWorkerConfig.
	IngestVulnLookupEnabled        bool          `env:"INGEST_VULN_LOOKUP_ENABLED"         envDefault:"true"`
	IngestVulnLookupMaxConcurrency int           `env:"INGEST_VULN_LOOKUP_MAX_CONCURRENCY" envDefault:"2"`
	OSVBaseURL                     string        `env:"OSV_BASE_URL"                       envDefault:"https://api.osv.dev"`
	OSVTimeout                     time.Duration `env:"OSV_TIMEOUT"                        envDefault:"30s"`
	OSVBatchSize                   int           `env:"OSV_BATCH_SIZE"                     envDefault:"1000"`
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

	// OCIDex API connection — the operator's only external dependency.
	ServerURL string `env:"OCIDEX_SERVER"`
	APIKey    string `env:"OCIDEX_API_KEY"`

	// OperatorNamespace is where the leader-election Lease is created. Distinct
	// from WatchNamespaces: this is where the operator runs, those are what it
	// reconciles. Supplied by the downward API (metadata.namespace) in both
	// deployment manifests.
	OperatorNamespace string `env:"OPERATOR_NAMESPACE"`

	// WatchNamespaces scopes the manager cache. Comma-separated because a
	// namespace-scoped operator that cuts straight over to a new namespace
	// strands the registry-protection finalizers it left behind: nothing
	// watches the old namespace any more, so handleDeletion never runs and the
	// namespace stays Terminating forever (ocidex-1eo). Listing both lets a
	// retarget add the new namespace, drain the old one, then drop it.
	WatchNamespaces []string `env:"WATCH_NAMESPACE" envSeparator:","`

	// Leader-election timings. These are deliberately wider than
	// controller-runtime's defaults of 15s/10s/2s. controller-runtime derives the
	// per-request API-server client timeout as max(RenewDeadline/2, 1s), so its
	// defaults allow only 5s for a single Lease GET — which a loaded control plane
	// can exceed, losing leadership and killing the process (ocidex-vh6). A 40s
	// renew deadline gives each request a 20s budget instead.
	LeaderElectionLeaseDuration time.Duration `env:"LEADER_ELECTION_LEASE_DURATION" envDefault:"60s"`
	LeaderElectionRenewDeadline time.Duration `env:"LEADER_ELECTION_RENEW_DEADLINE" envDefault:"40s"`
	LeaderElectionRetryPeriod   time.Duration `env:"LEADER_ELECTION_RETRY_PERIOD"   envDefault:"10s"`
}

// leaderElectionJitterFactor mirrors client-go's leaderelection.JitterFactor.
// The renew deadline must exceed RetryPeriod*JitterFactor, or client-go rejects
// the config when constructing the leader elector.
const leaderElectionJitterFactor = 1.2

// LoadOperator reads operator-specific configuration from environment variables.
func LoadOperator() (*OperatorConfig, error) {
	cfg := &OperatorConfig{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate enforces the same leader-election timing invariants client-go checks
// in NewLeaderElector, so a misconfiguration is reported at config load with the
// offending env var named rather than surfacing later from manager construction.
func (c *OperatorConfig) validate() error {
	// Checked separately rather than with env's `required` tag: `required` only
	// fires when the var is absent, and a secretKeyRef that resolves to an empty
	// string would satisfy it.
	if c.ServerURL == "" {
		return fmt.Errorf("OCIDEX_SERVER is required")
	}
	if c.APIKey == "" {
		return fmt.Errorf("OCIDEX_API_KEY is required")
	}
	if c.OperatorNamespace == "" {
		return fmt.Errorf("OPERATOR_NAMESPACE is required")
	}

	// env.Parse yields []string{""} for an unset var and keeps empty entries
	// from a trailing or doubled comma, so normalise before the required check
	// — an empty name in the cache config would silently widen the watch to
	// every namespace.
	watch := make([]string, 0, len(c.WatchNamespaces))
	for _, ns := range c.WatchNamespaces {
		if ns = strings.TrimSpace(ns); ns != "" {
			watch = append(watch, ns)
		}
	}
	c.WatchNamespaces = watch
	if len(c.WatchNamespaces) == 0 {
		return fmt.Errorf("WATCH_NAMESPACE is required")
	}

	if c.LeaderElectionLeaseDuration <= 0 || c.LeaderElectionRenewDeadline <= 0 || c.LeaderElectionRetryPeriod <= 0 {
		return fmt.Errorf("leader election durations must all be positive")
	}
	if c.LeaderElectionLeaseDuration <= c.LeaderElectionRenewDeadline {
		return fmt.Errorf(
			"LEADER_ELECTION_LEASE_DURATION (%s) must be greater than LEADER_ELECTION_RENEW_DEADLINE (%s)",
			c.LeaderElectionLeaseDuration, c.LeaderElectionRenewDeadline)
	}
	minRenew := time.Duration(float64(c.LeaderElectionRetryPeriod) * leaderElectionJitterFactor)
	if c.LeaderElectionRenewDeadline <= minRenew {
		return fmt.Errorf(
			"LEADER_ELECTION_RENEW_DEADLINE (%s) must be greater than LEADER_ELECTION_RETRY_PERIOD*%.1f (%s)",
			c.LeaderElectionRenewDeadline, leaderElectionJitterFactor, minRenew)
	}
	return nil
}

// SlogLevel returns the slog.Level for an OperatorConfig.
func (c *OperatorConfig) SlogLevel() slog.Level {
	return parseSlogLevel(c.LogLevel)
}

// K8sAgentConfig holds configuration for the cluster inventory agent
// (cmd/k8s-agent). Like the operator it talks only to the OCIDex API, but unlike
// the operator it runs *inside the cluster it reports on* — which may be a
// cluster that has no OCIDex deployment of its own (ADR-044 K1) — so it needs no
// database, no NATS, and no CRDs.
type K8sAgentConfig struct {
	LogLevel    string `env:"LOG_LEVEL"    envDefault:"info"`
	Environment string `env:"ENVIRONMENT"  envDefault:"development"`

	// OCIDex API connection — the agent's only external dependency.
	ServerURL string `env:"OCIDEX_SERVER"`
	APIKey    string `env:"OCIDEX_API_KEY"`

	// ClusterID is the OCIDex cluster this agent reports for. Supplied rather
	// than discovered: a Kubernetes cluster has no stable self-identifier the
	// agent could derive, and guessing one would let a redeployed agent silently
	// start replacing a different cluster's inventory.
	ClusterID string `env:"OCIDEX_CLUSTER_ID"`

	// Namespaces optionally restricts which Kubernetes namespaces are reported.
	// Empty means every namespace. Note the asymmetry with the snapshot contract:
	// a snapshot replaces the cluster's whole inventory (ADR-044 K7), so
	// *narrowing* this list on an existing agent prunes the namespaces it stops
	// reporting rather than leaving them behind as stale rows.
	Namespaces []string `env:"OCIDEX_NAMESPACES" envSeparator:","`

	// ReportInterval is the time between snapshots in long-running mode. Ignored
	// under --once.
	ReportInterval time.Duration `env:"OCIDEX_REPORT_INTERVAL" envDefault:"5m"`

	// HealthAddr is the liveness/readiness listen address, matching the other
	// workers' :9090 convention.
	HealthAddr string `env:"HEALTH_ADDR" envDefault:":9090"`
}

// LoadK8sAgent reads k8s-agent configuration from environment variables.
func LoadK8sAgent() (*K8sAgentConfig, error) {
	cfg := &K8sAgentConfig{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *K8sAgentConfig) validate() error {
	// Explicit emptiness checks rather than env's `required` tag, for the same
	// reason as OperatorConfig.validate: `required` passes on a secretKeyRef that
	// resolves to an empty string.
	if c.ServerURL == "" {
		return fmt.Errorf("OCIDEX_SERVER is required")
	}
	if c.APIKey == "" {
		return fmt.Errorf("OCIDEX_API_KEY is required")
	}
	if c.ClusterID == "" {
		return fmt.Errorf("OCIDEX_CLUSTER_ID is required")
	}
	if c.ReportInterval <= 0 {
		return fmt.Errorf("OCIDEX_REPORT_INTERVAL must be positive")
	}

	// env.Parse yields []string{""} for an unset var, which would otherwise read
	// as "one namespace, named empty string" and match nothing at all — the exact
	// inverse of the intended default of every namespace.
	ns := make([]string, 0, len(c.Namespaces))
	for _, n := range c.Namespaces {
		if n = strings.TrimSpace(n); n != "" {
			ns = append(ns, n)
		}
	}
	c.Namespaces = ns
	return nil
}

// SlogLevel returns the slog.Level for a K8sAgentConfig.
func (c *K8sAgentConfig) SlogLevel() slog.Level {
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
