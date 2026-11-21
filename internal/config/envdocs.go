// EnvDocs describes every environment variable OCIDex reads. It is the source the
// docs site's configuration reference is generated from (cmd/docgen, ADR-0057).
// TestEnvDocsMatchStructs keeps it in step with the env tags: a variable a struct
// reads must be described here, and every entry here must be read somewhere.

package config

import (
	"reflect"
	"slices"
	"strings"
)

// EnvDoc describes one environment variable for the configuration reference.
type EnvDoc struct {
	// Name is the variable, as it appears in an env tag.
	Name string
	// Group is the reference section it is listed under.
	Group string
	// Description is Markdown. Links to other docs pages are site-absolute.
	Description string
}

// EnvDocs lists every variable in reference order, grouped by Group.
var EnvDocs = []EnvDoc{
	{"DATABASE_URL", "Core", "PostgreSQL connection string. Apply migrations separately with `ocidex migrate up`; they do not run at startup."},
	{"PORT", "Core", "HTTP listen port."},
	{"LOG_LEVEL", "Core", "Log verbosity: `debug`, `info`, `warn`, `error`."},
	{"ENVIRONMENT", "Core", "Runtime environment label: `development`, `staging`, `production`."},
	{"DEV_AUTH_ENABLED", "Core", "Local development only. `true` registers `POST /api/v1/dev/session`, which mints a session for one of the personas seeded by `scripts/dev-auth.sh` without authentication. Requires `ENVIRONMENT=development`; startup fails with any other value. Never set it on a reachable instance."},
	{"SESSION_SECRET", "Authentication", "Cookie signing key. Required by the API. At least 32 bytes: shorter fails startup with `ENVIRONMENT=production` and logs a warning otherwise. Generate with: `openssl rand -hex 32`"},
	{"SESSION_MAX_AGE_DAYS", "Authentication", "How long login sessions last."},
	{"AUTH_RATE_LIMIT", "Authentication", "Requests per minute one client IP may make to `/auth/login*`, `/auth/callback*` and `POST /api/v1/auth/identities`. Over the limit: `429` with `Retry-After`. `0` disables. Counters are per API replica."},
	{"API_RATE_LIMIT_INGEST", "Authentication", "Requests per minute per principal to `POST /api/v1/sboms`. A principal is the user for an authenticated request (any of their sessions or API keys) and the client IP otherwise. Over the limit: `429` problem document with `Retry-After`. `0` disables. No role is exempt — raise this for an operator or CI key that pushes harder. Per API replica."},
	{"API_RATE_LIMIT_HEAVY", "Authentication", "Requests per minute per principal, one budget shared across the expensive reads: `/api/v1/artifacts/{id}/changelog`, `/api/v1/artifacts/{id}/vulns`, `/api/v1/artifacts/{id}/contains`, `/api/v1/components/versions`. `0` disables. Per API replica."},
	{"TRUSTED_PROXY_CIDRS", "Authentication", "Comma-separated CIDRs (or bare IPs) of reverse proxies whose `X-Forwarded-For` is believed when resolving a client IP for rate limiting. Only when the direct peer is inside these is the header read, and then the right-most hop outside them is the client. Empty: the direct peer is the client — behind an ingress, every request then shares the ingress's budget, so set this, `TRUSTED_PROXY_HOPS` or `CLIENT_IP_HEADER`. See [Client IP behind proxies](/guides/operate/production/#client-ips-behind-a-proxy)."},
	{"TRUSTED_PROXY_HOPS", "Authentication", "How many proxies stand in front of the API. The client is that many `X-Forwarded-For` entries from the right (`1` for a plain ingress). `0` is off."},
	{"CLIENT_IP_HEADER", "Authentication", "A header the edge overwrites with the client IP, such as `CF-Connecting-IP` or `True-Client-IP`. `X-Forwarded-For` is rejected; use `TRUSTED_PROXY_HOPS` for it."},
	{"SESSION_COOKIE_SAMESITE", "Authentication", "Session cookie `SameSite`: `lax`, `strict` or `none`. `none` is accepted only with `ENVIRONMENT=production` (it forces `Secure`). See below."},
	{"GITHUB_CLIENT_ID", "GitHub OAuth", "GitHub OAuth App client ID."},
	{"GITHUB_CLIENT_SECRET", "GitHub OAuth", "GitHub OAuth App client secret."},
	{"GITHUB_REDIRECT_URL", "GitHub OAuth", "OAuth callback URL. Must be registered in the GitHub OAuth App. When accessed via a non-localhost address (Tailscale, remote IP), set to that address."},
	{"OIDC_ISSUER_URL", "Generic OIDC", "Discovery base — the URL serving `/.well-known/openid-configuration`. Must match the `iss` claim exactly, and must be `https://` when `ENVIRONMENT=production`. Empty leaves OCIDex with whatever else is configured — with nothing else configured, the server will not start."},
	{"OIDC_CLIENT_ID", "Generic OIDC", "Required when `OIDC_ISSUER_URL` is set."},
	{"OIDC_CLIENT_SECRET", "Generic OIDC", "Omit for a public client; PKCE is always used regardless."},
	{"OIDC_NAME", "Generic OIDC", "Permanent key half of the `oidc:<name>` provider string stored against every account signed in through this issuer. **Changing it after the first login orphans those accounts.**"},
	{"OIDC_SCOPES", "Generic OIDC", "Comma-separated. `openid` is added if absent."},
	{"OIDC_REDIRECT_URL", "Generic OIDC", "The shared callback: the provider a sign-in began with rides in the signed state cookie, so one registered redirect URI serves every issuer. Point it at `/auth/callback/oidc:<name>` only for an IdP that insists on a distinct URI per client."},
	{"BOOTSTRAP_ADMINS", "First admin", "Comma-separated identities promoted to installation admin when they sign in: `github:<subject>` or `oidc:<name>:<subject>`. `<subject>` is the issuer's stable user id — the numeric GitHub user id (`gh api users/<login> --jq .id`), or the OIDC `sub` claim — and may itself contain colons. Matched on (provider, subject) only, never email ([ADR-047](https://github.com/pfenerty/ocidex/blob/main/docs/adr/0047-provider-agnostic-identity.md)). A malformed entry fails startup."},
	{"SIGNUP_MODE", "Installation policy", "`open` creates an account (global role `viewer`) for any identity a configured issuer vouches for — any GitHub account, with GitHub. `existing` signs in only identities that already have an account, plus `BOOTSTRAP_ADMINS`; anyone else gets 401 at the callback."},
	{"SELF_SERVICE_NAMESPACES", "Installation policy", "Whether a global `viewer` may create a namespace, either directly or by creating a registry without naming an existing namespace. `false` restricts both to global `member` and `admin` (403 otherwise)."},
	{"FRONTEND_URL", "Frontend / CORS", "Post-login redirect target and CORS default. With `ENVIRONMENT=production` the redirect is this URL exactly. Outside production the redirect follows the login request's hostname with this URL's port — so several dev hostnames work — but only when that origin is in `CORS_ALLOWED_ORIGINS`; any other host falls back to this URL."},
	{"DISCOVER_FEATURED", "Frontend / CORS", "Comma-separated artifact names the landing page features as cards, in this order. An entry matches an artifact named exactly that or ending in `/<entry>`, so `library/nginx` finds `registry-1.docker.io/library/nginx`; only artifacts with a public SBOM qualify. Empty: the public container images with the most packages."},
	{"CORS_ALLOWED_ORIGINS", "Frontend / CORS", "Comma-separated CORS origins, each a bare `scheme://host[:port]` (no path, not even `/`). Empty falls back to `FRONTEND_URL`. With `ENVIRONMENT=production` a `*` or a malformed entry fails startup; in development `*` is only warned about. The same set decides which origins may send cookie-authenticated writes."},
	{"API_BASE_URL", "Frontend / CORS", "Public base URL of the API, used to populate the OpenAPI `servers` block for tooling/docs. Optional."},
	{"DATABASE_MAX_CONNECTIONS", "Database Pool", "pgx connection pool size. Reduce for worker processes (2–5 is typical)."},
	{"ENRICHMENT_ENABLED", "Enrichment Pipeline", "Read by the per-enricher workers; gates whether they consume enrichment jobs. Has no effect on the API process."},
	{"ENRICHMENT_MAX_CONCURRENCY", "Enrichment Pipeline", "Enrichment jobs each enricher worker process runs at once."},
	{"ENRICHMENT_POLL_INTERVAL", "Enrichment Pipeline", "How often each enricher worker checks the database for queued jobs when no NATS hint arrives. This is what keeps the queue draining while NATS is down."},
	{"ENRICHMENT_STUCK_THRESHOLD", "Enrichment Pipeline", "How long a `running` job can go without a heartbeat before the sweep requeues it, or fails it if its attempts are used up."},
	{"ENRICHMENT_MAX_ATTEMPTS", "Enrichment Pipeline", "Attempts per job before it is left `failed` for the Jobs page's Retry button."},
	{"ENRICHMENT_WORKERS", "Enrichment Pipeline", "**Deprecated, removed in 2.0 (ocidex-lwow).** Has no effect; the process logs a warning when it is set. Use `ENRICHMENT_MAX_CONCURRENCY`."},
	{"ENRICHMENT_QUEUE_SIZE", "Enrichment Pipeline", "**Deprecated, removed in 2.0 (ocidex-lwow).** Has no effect; the queue is the `enrichment_jobs` table, which has no depth limit. The process logs a warning when it is set."},
	{"SCANNER_ENABLED", "OCI Registry Scanner", "On the API, enables publishing scan requests (required for both webhook and poll scan modes). The API never scans in-process, so a `scanner-worker` must run to consume the requests."},
	{"SCANNER_MAX_CONCURRENCY", "OCI Registry Scanner", "Scans each `scanner-worker` process runs at once. Each holds an image's layers in memory, so size `limits.memory` for this many."},
	{"SCANNER_POLL_INTERVAL", "OCI Registry Scanner", "How often each `scanner-worker` checks the database for queued `scan_jobs` when no NATS hint arrives."},
	{"SCANNER_STUCK_THRESHOLD", "OCI Registry Scanner", "How long a `running` scan job can go without a heartbeat before the sweep requeues it, or fails it if its attempts are used up."},
	{"SCANNER_MAX_ATTEMPTS", "OCI Registry Scanner", "Attempts per scan job before it is left `failed`. A failed job is not requeued automatically; Retry it from the Jobs page."},
	{"SCANNER_MAX_IMAGE_BYTES", "OCI Registry Scanner", "Largest image the worker hands to Syft, as total *compressed* layer bytes read from its manifest. Above this the job fails permanently without pulling anything — Syft unpacks every layer, so an image past what `limits.memory` can hold OOMKills the container instead of returning an error, taking any concurrent scan with it. Raise this and the memory limit together; `0` disables the check."},
	{"SCANNER_GO_SYMBOLS", "OCI Registry Scanner", "Which Go binary packages get their linked function symbols captured, for symbol-level vulnerability matching ([ADR-050](https://github.com/pfenerty/ocidex/blob/main/docs/adr/0050-go-symbol-level-vulnerability-matching.md)): `none`, `stdlib`, `extended-stdlib` or `all`. `all` is needed to filter third-party module advisories, not just the standard library's. A large Go image links ~1M symbols; the scan holds them in memory briefly and ingest stores them deduplicated."},
	{"REGISTRY_POLLER_ENABLED", "OCI Registry Scanner", "Enable the background poller for registries with `scan_mode=poll` or `scan_mode=both`. Requires `SCANNER_ENABLED=true`. Uses leader election so multiple API replicas are safe."},
	{"DATA_ENCRYPTION_KEYS", "Credential Encryption", "Comma-separated `<id>:<base64 32-byte key>`. Every key listed can decrypt. An id is `[A-Za-z0-9_-]{1,32}`. Generate a key with `openssl rand -base64 32`. **Required when `ENVIRONMENT=production`**; without it, startup fails. Outside production, unset means credentials are stored in plaintext and the API logs a warning."},
	{"DATA_ENCRYPTION_ACTIVE_KEY", "Credential Encryption", "The key id new values are encrypted with. Must name a key in `DATA_ENCRYPTION_KEYS`."},
	{"EGRESS_ALLOW_PRIVATE", "Egress Policy", "Allow private addresses: `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT), `198.18/15`, `fc00::/7`, and the NAT64 local-use prefix `64:ff9b:1::/48`. This opens everything on the cluster network too (the Kubernetes API, Postgres, NATS, OCIDex's own pods). Prefer `EGRESS_ALLOW_CIDRS` naming just the registry."},
	{"EGRESS_ALLOW_CIDRS", "Egress Policy", "Comma-separated CIDRs (or bare IPs) always reachable. The preferred way to reach an in-cluster or LAN registry. Also the only way to reach the always-refused ranges: loopback, link-local (`169.254/16`, including cloud metadata), multicast, reserved and IETF-assigned IPv4 ranges, and Teredo."},
	{"EGRESS_DENY_CIDRS", "Egress Policy", "Comma-separated CIDRs refused in addition to the built-in ranges, e.g. the cluster's service CIDR when `EGRESS_ALLOW_PRIVATE=true`. An allow entry still wins."},
	{"PROVENANCE_REVERIFIER_ENABLED", "Provenance Reverification", "Enable the background provenance recheck sweep. Uses leader election so multiple API replicas are safe."},
	{"PROVENANCE_RECHECK_INTERVAL", "Provenance Reverification", "How old a SBOM's last successful provenance check must be before it's requeued. Also controls the sweep's tick rate."},
	{"PROVENANCE_TIMEOUT", "Provenance Reverification", "Bounds one provenance enrichment end to end: the existence HEAD, referrers discovery and its child layer fetches, the Rekor lookup, and cosign verification (which may itself refresh the Sigstore trusted root, allowed 30s of its own). The phases share one budget deliberately — giving each its own would leave total wall clock unbounded across a variable number of child fetches. A mid-chain expiry costs a retry, so raise this when provenance error rates climb against a slow registry. The Rekor lookup is the one exception: it is scoped to 10s of the budget, because it is fail-open and should never be able to starve verification."},
	{"PROVENANCE_MAX_LAYER_BYTES", "Provenance Reverification", "Read budget for one manifest's signature layers, and separately for one manifest's attestation layers. The layers are registry-controlled and read whole into memory — a bare cosign signature is a few KB, an attestation carrying a full SBOM is megabytes — and reading one unbounded is what OOMKilled the worker. It is a budget shared across a manifest's layers, not a per-layer cap: a `.sig` manifest holds one layer per signature and every one is read, so a per-layer cap would multiply the ceiling by the layer count. A manifest listing more than 32 layers is rejected outright. Exceeding either fails that job with a diagnosable error, not the pod. Raise the worker's memory limit alongside this."},
	{"GIT_MAX_RESPONSE_BYTES", "Provenance Reverification", "Largest GitHub API response body the git enricher will read. Same reasoning as `PROVENANCE_MAX_LAYER_BYTES`: a remote-controlled body read whole into memory puts the worker's memory limit in someone else's hands. A successful response over the cap fails that job; an oversized *error* body is truncated into the message so the status code is not lost."},
	{"RETENTION_MODE", "SBOM Retention", "`off`, `dry-run` or `on`. `dry-run` logs what each sweep would delete and deletes nothing."},
	{"RETENTION_KEEP_LAST", "SBOM Retention", "For SBOMs that don't come from a registry walk (uploads, auto-ingested and direct scans): versions kept per artifact and flavor in each namespace. `0` turns this class off; any other value must be at least `2`."},
	{"RETENTION_MAX_AGE", "SBOM Retention", "Optional, same SBOMs: also prune versions ingested longer ago than this Go duration (`2160h` is 90 days)."},
	{"RETENTION_REGISTRY_WINDOW", "SBOM Retention", "Prune registry SBOMs whose tag has left the registry's scan window (`tag_limit`, `max_tag_age_days`) at its last successful walk."},
	{"RETENTION_INTERVAL", "SBOM Retention", "Gap between sweeps."},
	{"RETENTION_BATCH", "SBOM Retention", "SBOMs deleted per transaction. Each SBOM cascades into its components and their children, so keep this small."},
	{"NATS_URL", "NATS JetStream", "**Required.** NATS server connection URL."},
	{"NATS_STREAM_NAME", "NATS JetStream", "JetStream stream name."},
	{"NATS_EVENT_TTL_HOURS", "NATS JetStream", "How long events are retained in the stream."},
	{"NATS_STREAM_REPLICAS", "NATS JetStream", "JetStream stream replica count. Set to `3` for a 3-node NATS cluster."},
	{"AUDIT_LOG_ENABLED", "Audit Logging", "Write a structured `audit` log line to stdout for each SBOM ingest and delete, artifact delete, login, logout and retention sweep. See [Monitoring](/guides/operate/monitoring/#audit-log)."},
	{"METRICS_ADDR", "Metrics", "Listen address for `/metrics`. Empty disables the listener and metrics."},
	{"OTEL_RESOURCE_ATTRIBUTES", "Metrics", "Extra resource attributes, e.g. `deployment.environment.name=prod`. They appear on the `target_info` series and on every span."},
	{"OTEL_METRICS_EXPORTER", "Metrics", "Comma-separated: `prometheus` serves `/metrics`, `otlp` also pushes to `OTEL_EXPORTER_OTLP_*`, `none` turns metrics off."},
	{"OTEL_TRACES_EXPORTER", "Tracing", "`otlp` exports spans to `OTEL_EXPORTER_OTLP_*`; `console` prints them to stdout."},
	{"OTEL_TRACES_SAMPLER", "Tracing", "Sampler. Defaults to `parentbased_traceidratio`, which keeps a fraction of new traces; spans with a parent follow it, so a trace is kept or dropped whole."},
	{"OTEL_TRACES_SAMPLER_ARG", "Tracing", "The sampler's argument. Defaults to `0.1`: keep 10% of new traces."},
	{"OTEL_EXPORTER_OTLP_ENDPOINT", "Tracing", "Collector address for traces, and for metrics when `OTEL_METRICS_EXPORTER` includes `otlp`. `_PROTOCOL` (`http/protobuf` or `grpc`) and `_HEADERS` work as usual."},
	{"SCAN_IMAGE", "scanner-worker one-shot jobs", "**Required.** Full image reference: `registry/repo:tag@sha256:digest`"},
	{"SCAN_REGISTRY_ID", "scanner-worker one-shot jobs", "Optional UUID of the OCIDex registry record to associate the SBOM with."},
	{"SCAN_INSECURE", "scanner-worker one-shot jobs", "`true` to allow HTTP/insecure registries."},
	{"SCAN_AUTH_USERNAME", "scanner-worker one-shot jobs", "Registry auth username."},
	{"SCAN_AUTH_TOKEN", "scanner-worker one-shot jobs", "Registry auth token/password."},
	{"ENRICH_SBOM_ID", "Enricher worker one-shot jobs", "**Required.** UUID of the SBOM to enrich."},
	{"VULN_REFRESH_ENABLED", "vuln-worker", "Gates the scheduled refresh loop."},
	{"VULN_REFRESH_INTERVAL", "vuln-worker", "Minimum time between refreshes."},
	{"VULN_DB_DIR", "vuln-worker", "Where the grype database is installed (~3 GB). An update needs room for the download plus two copies, so give it ~10 GiB. In Kubernetes this is a PVC (`vulnWorker.db.persistence`); use node-local storage, not NFS, because the database is SQLite."},
	{"VULN_DB_UPDATE_URL", "vuln-worker", "Listing checked for newer databases (`https://grype.anchore.io/databases`). Point it at a self-hosted `grype-db` build to control the source."},
	{"VULN_DB_MAX_AGE", "vuln-worker", "Reject a database built longer ago than this. grype publishes daily."},
	{"OCIDEX_SERVER", "k8s-agent", "**Required.** OCIDex API base URL, e.g. `https://ocidex.example.com`."},
	{"OCIDEX_API_KEY", "k8s-agent", "**Required.** API key carrying the `push_inventory` capability, owned by a member whose role on the cluster's namespace grants it."},
	{"OCIDEX_CLUSTER_ID", "k8s-agent", "**Required.** UUID of the registered `cluster` this agent reports for. Supplied rather than discovered: a Kubernetes cluster has no stable self-identifier, and a defaulted one could replace the wrong cluster's inventory."},
	{"OCIDEX_NAMESPACES", "k8s-agent", "Comma-separated Kubernetes namespace allowlist. Empty means every namespace."},
	{"OCIDEX_REPORT_INTERVAL", "k8s-agent", "Time between snapshots. Ignored under `--once`."},
	{"HEALTH_ADDR", "k8s-agent", "Liveness/readiness listen address (`/healthz`, `/readyz`)."},
	{"POD_NAME", "k8s-agent", "The agent's own pod name, reported with each snapshot so the cluster page names the pod to inspect. The chart sets it from the downward API."},
	{"POD_NAMESPACE", "k8s-agent", "The namespace the agent runs in, reported alongside `POD_NAME`. The chart sets it from the downward API."},
	{"OPERATOR_NAMESPACE", "operator", "Where the leader-election Lease lives. The chart sets it from the pod's own namespace."},
	{"WATCH_NAMESPACE", "operator", "Comma-separated namespaces whose `OCIRegistry`, `ScanRequest` and `APIKey` objects the operator reconciles. Empty watches every namespace. List the old and new namespaces together while retargeting, or the old namespace's finalizers are never removed (see [Changing what it watches](/guides/operate/clusters-and-operator/#changing-what-it-watches-or-removing-it))."},
	{"LEADER_ELECTION_LEASE_DURATION", "operator", "Leader-election lease length."},
	{"LEADER_ELECTION_RENEW_DEADLINE", "operator", "How long the leader keeps retrying a renewal before giving up leadership. Wider than controller-runtime's 10s, because each renewal request gets half this as its timeout, and 5s is too little on a loaded control plane (ocidex-vh6)."},
	{"LEADER_ELECTION_RETRY_PERIOD", "operator", "How often candidates retry acquiring the lease."},
}

// DocumentedStructs is every config struct whose env tags EnvDocs must cover.
func DocumentedStructs() []any {
	return []any{Config{}, VulnWorkerConfig{}, OperatorConfig{}, K8sAgentConfig{}}
}

// EnvVar is what the env tags themselves say about a variable.
type EnvVar struct {
	Name     string
	Default  string
	Required bool
}

// EnvVars returns every env-tagged variable of the documented structs, keyed by
// name. A variable two structs share keeps the first declaration it meets.
func EnvVars() map[string]EnvVar {
	out := map[string]EnvVar{}
	for _, v := range DocumentedStructs() {
		collectEnvVars(reflect.TypeOf(v), out)
	}
	return out
}

func collectEnvVars(typ reflect.Type, into map[string]EnvVar) {
	for f := range typ.Fields() {
		if tag, ok := f.Tag.Lookup("env"); ok {
			name, opts, _ := strings.Cut(tag, ",")
			if _, seen := into[name]; name != "" && !seen {
				into[name] = EnvVar{
					Name:     name,
					Default:  f.Tag.Get("envDefault"),
					Required: slices.Contains(strings.Split(opts, ","), "required"),
				}
			}
		}
		if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == typ.PkgPath() {
			collectEnvVars(f.Type, into)
		}
	}
}
