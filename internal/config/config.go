// Package config handles application configuration loaded from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"

	"github.com/pfenerty/ocidex/internal/netguard"
	"github.com/pfenerty/ocidex/internal/secretbox"
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

	// Generic OIDC. Setting OIDC_ISSUER_URL is what enables the provider;
	// leaving it empty leaves OCIDex GitHub-only, exactly as before.
	OIDCIssuerURL    string `env:"OIDC_ISSUER_URL"`
	OIDCClientID     string `env:"OIDC_CLIENT_ID"`
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET"`
	// OIDCName is the permanent key half of the "oidc:<name>" provider string
	// stored against every account that signs in through this issuer. Changing
	// it after the first login orphans those accounts.
	OIDCName   string   `env:"OIDC_NAME"   envDefault:"oidc"`
	OIDCScopes []string `env:"OIDC_SCOPES" envSeparator:","`
	// OIDCRedirectURL defaults to the shared callback: the provider a sign-in
	// began with rides in the signed state cookie, so one registered redirect
	// URI serves every issuer. Point it at /auth/callback/oidc:<name> only for
	// an IdP that insists on a distinct URI per client.
	OIDCRedirectURL string `env:"OIDC_REDIRECT_URL" envDefault:"http://localhost:8080/auth/callback"`

	// BootstrapAdminsRaw lists the identities promoted to installation admin
	// when they sign in: comma-separated "github:<subject>" or
	// "oidc:<name>:<subject>". It is how an installation gets its first admin.
	// Matched on (provider, subject) only, never email (ADR-047). Parsed into
	// BootstrapAdmins by validate.
	BootstrapAdminsRaw string `env:"BOOTSTRAP_ADMINS"`
	BootstrapAdmins    []IdentityRef

	// SignupMode is the installation's sign-up policy: "open" provisions an
	// account for any identity the configured issuers vouch for; "existing"
	// admits only identities that already have one, plus BOOTSTRAP_ADMINS.
	// Empty (a Config not built by Load) reads as open.
	SignupMode string `env:"SIGNUP_MODE" envDefault:"open"`

	// SelfServiceNamespacesRaw is SELF_SERVICE_NAMESPACES: whether a global
	// viewer may create a namespace (directly, or by creating a registry that
	// mints one). validate turns it into RestrictNamespaceCreation, which is
	// inverted so a zero Config keeps today's open behaviour.
	SelfServiceNamespacesRaw  string `env:"SELF_SERVICE_NAMESPACES" envDefault:"true"`
	RestrictNamespaceCreation bool

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
	// ScannerMaxImageBytes is the largest image the worker will hand to syft,
	// measured as the total *compressed* layer size its manifest advertises.
	// Syft has to pull and unpack every layer, so an image past what the pod's
	// memory limit can hold does not fail — the container is OOMKilled, which
	// records no error on the row and takes any concurrent scan down with it.
	// The row is then reaped by the stuck sweep and retried, so one oversized
	// image degrades the whole worker on a loop. Checking the manifest first
	// costs one small GET and converts that into a single 'failed' row that
	// says why. Keep it below what limits.memory can actually catalogue; 0
	// disables the check.
	ScannerMaxImageBytes int64 `env:"SCANNER_MAX_IMAGE_BYTES" envDefault:"2147483648"`

	// ScannerGoSymbols selects which Go binary packages get their linked function
	// symbols captured for symbol-level vulnerability matching (ADR-050): none,
	// stdlib, extended-stdlib or all. "all" is needed to filter third-party module
	// advisories, not just the standard library's.
	ScannerGoSymbols string `env:"SCANNER_GO_SYMBOLS" envDefault:"all"`

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

	// ProvenanceTimeout bounds one provenance enrichment end to end: the
	// existence HEAD, referrers discovery and its child layer fetches, the
	// Rekor lookup, and cosign verification (which may itself refresh the
	// Sigstore trusted root). The phases share one budget deliberately — giving
	// each its own would leave total wall clock unbounded across a variable
	// number of child fetches. 30s was too tight for that whole chain against a
	// slow registry, and a mid-chain expiry costs a retry (ocidex-zvkx), so the
	// default is the lever to raise when provenance error rates climb.
	ProvenanceTimeout time.Duration `env:"PROVENANCE_TIMEOUT" envDefault:"90s"`

	// ProvenanceMaxLayerBytes caps the signature layers of one manifest, and
	// separately the attestation layers of one manifest, that the provenance
	// enricher will read. The layers are registry-controlled and read whole into
	// memory: a bare cosign signature is a few KB, an attestation carrying a full
	// SBOM is megabytes, and reading one unbounded is what OOMKilled the worker
	// (ocidex-wvnp). Exceeding it fails that job, not the pod. Raising it means
	// raising the worker's memory limit too.
	//
	// It is a budget shared across a manifest's layers rather than a per-layer
	// cap: a .sig manifest holds one layer per signature and all of them are read
	// (ocidex-r27f), so a per-layer cap would multiply the ceiling by the layer
	// count.
	ProvenanceMaxLayerBytes int64 `env:"PROVENANCE_MAX_LAYER_BYTES" envDefault:"16777216"` // 16MiB

	// GitMaxResponseBytes caps the GitHub API response body the git enricher
	// will read. Same reasoning as ProvenanceMaxLayerBytes: a remote-controlled
	// body read whole into memory is the worker's memory limit in someone
	// else's hands. Exceeding it fails that job, not the pod.
	GitMaxResponseBytes int64 `env:"GIT_MAX_RESPONSE_BYTES" envDefault:"4194304"` // 4MiB

	// ProvenanceReverifierEnabled gates the provenance recheck sweep. Defaults
	// to true since it already runs unconditionally today; set to false to
	// disable (e.g. in a test/staging environment without registry access).
	ProvenanceReverifierEnabled bool `env:"PROVENANCE_REVERIFIER_ENABLED" envDefault:"true"`

	// Egress policy for dials to user-supplied hosts (registries), shared by the
	// API, scanner worker and enrichers. Loopback, link-local (cloud metadata)
	// and multicast are always refused unless EGRESS_ALLOW_CIDRS names them;
	// private ranges are refused unless EGRESS_ALLOW_PRIVATE is set. See
	// internal/netguard.
	EgressAllowPrivate bool     `env:"EGRESS_ALLOW_PRIVATE" envDefault:"false"`
	EgressAllowCIDRs   []string `env:"EGRESS_ALLOW_CIDRS"   envSeparator:","`
	EgressDenyCIDRs    []string `env:"EGRESS_DENY_CIDRS"    envSeparator:","`
	// EgressPolicy is built from the three fields above by validate.
	EgressPolicy netguard.Policy

	// Encryption of stored registry credentials (ADR-051).
	// DATA_ENCRYPTION_KEYS is "<id>:<base64 32 bytes>,..."; every listed key
	// decrypts, DATA_ENCRYPTION_ACTIVE_KEY names the one that encrypts.
	DataEncryptionKeys      string `env:"DATA_ENCRYPTION_KEYS"` //nolint:gosec
	DataEncryptionActiveKey string `env:"DATA_ENCRYPTION_ACTIVE_KEY"`
	// SecretBox is built from the two fields above by validate. Nil means no
	// key is configured, which validate allows only outside production.
	SecretBox *secretbox.Box
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
// (cmd/vuln-worker). It talks only to Postgres and the grype database listing —
// no NATS — so it has its own loader rather than the NATS-requiring Config.
type VulnWorkerConfig struct {
	LogLevel         string `env:"LOG_LEVEL"    envDefault:"info"`
	Environment      string `env:"ENVIRONMENT"  envDefault:"development"`
	DatabaseURL      string `env:"DATABASE_URL,required"`
	DatabaseMaxConns int    `env:"DATABASE_MAX_CONNECTIONS" envDefault:"5"`

	// RefreshEnabled gates the scheduled refresh loop.
	RefreshEnabled bool `env:"VULN_REFRESH_ENABLED" envDefault:"true"`
	// RefreshInterval is how often the leader checks for a newer grype database
	// build; a new build triggers a full re-match. Newly ingested SBOMs are
	// matched within a minute regardless.
	RefreshInterval time.Duration `env:"VULN_REFRESH_INTERVAL" envDefault:"6h"`

	// VulnDBDir is where the grype vulnerability database is installed (ADR-049).
	// About 3 GB, and an update briefly needs room for two copies plus the download,
	// so in-cluster it is a persistent volume.
	VulnDBDir string `env:"VULN_DB_DIR" envDefault:"/var/lib/ocidex/grype-db"`
	// VulnDBUpdateURL overrides the listing grype checks for newer databases
	// (empty = grype's default, https://grype.anchore.io/databases).
	VulnDBUpdateURL string `env:"VULN_DB_UPDATE_URL"`
	// VulnDBMaxAge rejects a database built longer ago than this; grype publishes daily.
	VulnDBMaxAge time.Duration `env:"VULN_DB_MAX_AGE" envDefault:"120h"`
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

// Sign-up modes for SIGNUP_MODE.
const (
	SignupOpen     = "open"
	SignupExisting = "existing"
)

// IdentityRef names one sign-in identity by its user_identity key.
type IdentityRef struct {
	Provider string
	Subject  string
}

// ParseIdentityRefs parses a comma-separated list of "github:<subject>" or
// "oidc:<name>:<subject>" entries. The subject is everything after the
// provider, so a subject containing colons survives. Blank entries are
// skipped; anything else malformed is an error naming the entry.
func ParseIdentityRefs(raw string) ([]IdentityRef, error) {
	var refs []IdentityRef
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		head, rest, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("%q: want github:<subject> or oidc:<name>:<subject>", entry)
		}
		var ref IdentityRef
		switch head {
		case "github":
			ref = IdentityRef{Provider: "github", Subject: rest}
		case "oidc":
			name, subject, ok := strings.Cut(rest, ":")
			if !ok || name == "" {
				return nil, fmt.Errorf("%q: want oidc:<name>:<subject>", entry)
			}
			ref = IdentityRef{Provider: "oidc:" + name, Subject: subject}
		default:
			return nil, fmt.Errorf("%q: unknown provider %q (want github or oidc)", entry, head)
		}
		if ref.Subject == "" {
			return nil, fmt.Errorf("%q: subject is empty", entry)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func (c *Config) validate() error {
	if c.NATSURL == "" {
		return fmt.Errorf("NATS_URL is required")
	}
	admins, err := ParseIdentityRefs(c.BootstrapAdminsRaw)
	if err != nil {
		return fmt.Errorf("BOOTSTRAP_ADMINS: %w", err)
	}
	c.BootstrapAdmins = admins
	switch c.SignupMode {
	case SignupOpen, SignupExisting:
	default:
		return fmt.Errorf("SIGNUP_MODE must be %q or %q, got %q", SignupOpen, SignupExisting, c.SignupMode)
	}
	selfService, err := strconv.ParseBool(c.SelfServiceNamespacesRaw)
	if err != nil {
		return fmt.Errorf("SELF_SERVICE_NAMESPACES must be true or false, got %q", c.SelfServiceNamespacesRaw)
	}
	c.RestrictNamespaceCreation = !selfService
	if c.EgressPolicy, err = egressPolicy(c.EgressAllowPrivate, c.EgressAllowCIDRs, c.EgressDenyCIDRs); err != nil {
		return err
	}
	if c.SecretBox, err = secretbox.Parse(c.DataEncryptionKeys, c.DataEncryptionActiveKey); err != nil {
		return fmt.Errorf("DATA_ENCRYPTION_KEYS: %w", err)
	}
	if c.SecretBox == nil && c.Environment == "production" {
		return fmt.Errorf("DATA_ENCRYPTION_KEYS is required when ENVIRONMENT=production (ADR-051)")
	}
	// Half-configured OIDC is worse than none: the login button would exist
	// and fail. Discovery itself is validated at startup in cmd/ocidex.
	if c.OIDCIssuerURL != "" && c.OIDCClientID == "" {
		return fmt.Errorf("OIDC_CLIENT_ID is required when OIDC_ISSUER_URL is set")
	}
	if c.OIDCIssuerURL == "" && c.OIDCClientID != "" {
		return fmt.Errorf("OIDC_ISSUER_URL is required when OIDC_CLIENT_ID is set")
	}
	return nil
}

// egressPolicy builds a netguard.Policy from the EGRESS_* settings, naming the
// variable that holds a bad CIDR.
func egressPolicy(allowPrivate bool, allow, deny []string) (netguard.Policy, error) {
	allowP, err := netguard.ParsePrefixes(trimAll(allow))
	if err != nil {
		return netguard.Policy{}, fmt.Errorf("EGRESS_ALLOW_CIDRS: %w", err)
	}
	denyP, err := netguard.ParsePrefixes(trimAll(deny))
	if err != nil {
		return netguard.Policy{}, fmt.Errorf("EGRESS_DENY_CIDRS: %w", err)
	}
	return netguard.Policy{AllowCIDRs: allowP, DenyCIDRs: denyP, AllowPrivate: allowPrivate}, nil
}

func trimAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.TrimSpace(s)
	}
	return out
}

// LogLevel returns the slog.Level corresponding to the configured log level string.
func (c *Config) SlogLevel() slog.Level {
	return parseSlogLevel(c.LogLevel)
}
