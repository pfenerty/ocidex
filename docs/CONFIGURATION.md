# Configuration Reference

OCIDex is configured entirely via environment variables. The API server, scanner worker, and enricher workers all share the same `Config` struct (`internal/config/config.go`) and load from the process environment.

## Architecture

OCIDex runs as independent processes wired together by NATS JetStream.
The API process publishes work; the workers consume it. `NATS_URL` is required
for every process — there is no in-process/single-binary mode.

```
┌──────────────────┐     ┌─────────┐     ┌───────────────────────┐
│  ocidex API      │────▶│  NATS   │────▶│  scanner-worker       │
│  (publishes jobs)│     │JetStream│     │  oci-metadata-worker  │
│  + registry poll │     └─────────┘     │  user-enricher-worker │
└──────────────────┘                     │  provenance-worker    │
                                         └───────────────────────┘
```

Database migrations are **not** run at startup; apply them explicitly with
`ocidex migrate up` (a subcommand of the API binary) before rolling out a new
schema. See `docs/DEPLOYMENT.md`.

---

## Environment Variables

### Core

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `DATABASE_URL` | — | **yes** | PostgreSQL connection string. Apply migrations separately with `ocidex migrate up`; they do not run at startup. |
| `PORT` | `8080` | no | HTTP listen port. |
| `LOG_LEVEL` | `info` | no | Log verbosity: `debug`, `info`, `warn`, `error`. |
| `ENVIRONMENT` | `development` | no | Runtime environment label: `development`, `staging`, `production`. |

### Authentication

OCIDex authenticates against one or more *providers*. A provider is keyed `github` or
`oidc:<name>`, and that key is stored against every account that signs in through it —
identity is matched on `(provider, subject)` and never on email. See
[ADR-047](adr/0047-provider-agnostic-identity.md).

No individual provider is required: configure GitHub, an OIDC issuer, or both. What the
server does require is that it ends up with at least one — it refuses to start with an
empty provider list rather than serve a login page nobody can get past. `SESSION_SECRET`
is required in every case, because it signs the cookies every provider's flow depends on.

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_SECRET` | — | Cookie signing key. Required. Min 32 bytes. Generate with: `openssl rand -hex 32` |
| `SESSION_MAX_AGE_DAYS` | `7` | How long login sessions last. |
| `AUTH_RATE_LIMIT` | `30` | Requests per minute one client IP may make to `/auth/login*`, `/auth/callback*` and `POST /api/v1/auth/identities`. Over the limit: `429` with `Retry-After`. `0` disables. Counters are per API replica. |
| `API_RATE_LIMIT_INGEST` | `120` | Requests per minute per principal to `POST /api/v1/sboms`. A principal is the user for an authenticated request (any of their sessions or API keys) and the client IP otherwise. Over the limit: `429` problem document with `Retry-After`. `0` disables. No role is exempt — raise this for an operator or CI key that pushes harder. Per API replica. |
| `API_RATE_LIMIT_HEAVY` | `120` | Requests per minute per principal, one budget shared across the expensive reads: `/api/v1/artifacts/{id}/changelog`, `/api/v1/artifacts/{id}/vulns`, `/api/v1/artifacts/{id}/contains`, `/api/v1/components/versions`. `0` disables. Per API replica. |
| `TRUSTED_PROXY_CIDRS` | `""` | Comma-separated CIDRs (or bare IPs) of reverse proxies whose `X-Forwarded-For` is believed when resolving a client IP for rate limiting. Only when the direct peer is inside these is the header read, and then the right-most hop outside them is the client. Empty: the direct peer is the client — behind an ingress, every request then shares the ingress's budget, so set this to the ingress's pod/node range. |
| `SESSION_COOKIE_SAMESITE` | `lax` | Session cookie `SameSite`: `lax`, `strict` or `none`. `none` is accepted only with `ENVIRONMENT=production` (it forces `Secure`). See below. |

`SameSite` is decided by **site**, not origin: two hosts are same-site when they share a
registrable domain, so `ocidex.example.com` serving the SPA and `api.ocidex.example.com`
serving the API are same-site and work with the default `lax`, which also stops most
cross-site request forgery on its own. Set `none` only when the SPA is on a different
registrable domain from the API (say `ocidex-ui.net` against `api.ocidex.example.com`) —
the browser will not send a `lax` cookie on those cross-site fetches, and every API call
will look signed out. `strict` additionally withholds the cookie on top-level navigation
from another site, so a link into OCIDex from elsewhere lands signed out until the SPA's
first API call.

#### GitHub OAuth

Set both vars to enable GitHub login, or neither to leave it off. Setting one without the
other is a startup error rather than a silent disable, because half a credential pair is a
typo far more often than it is an intent.

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_CLIENT_ID` | — | GitHub OAuth App client ID. |
| `GITHUB_CLIENT_SECRET` | — | GitHub OAuth App client secret. |
| `GITHUB_REDIRECT_URL` | `http://localhost:8080/auth/callback` | OAuth callback URL. Must be registered in the GitHub OAuth App. When accessed via a non-localhost address (Tailscale, remote IP), set to that address. |

#### Generic OIDC

Additive: GitHub stays available whether or not this is set, and this is enough on its own
if GitHub is not configured. Setting `OIDC_ISSUER_URL` is what enables the provider, and one
implementation covers Google, Okta, Entra, Keycloak, Auth0 and GitLab.

Discovery runs at **startup**. A wrong issuer URL stops the process with a clear error rather
than producing a login button that fails on click.

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_ISSUER_URL` | `""` | Discovery base — the URL serving `/.well-known/openid-configuration`. Must match the `iss` claim exactly. Empty leaves OCIDex with whatever else is configured — with nothing else configured, the server will not start. |
| `OIDC_CLIENT_ID` | — | Required when `OIDC_ISSUER_URL` is set. |
| `OIDC_CLIENT_SECRET` | `""` | Omit for a public client; PKCE is always used regardless. |
| `OIDC_NAME` | `oidc` | Permanent key half of the `oidc:<name>` provider string stored against every account signed in through this issuer. **Changing it after the first login orphans those accounts.** |
| `OIDC_SCOPES` | `openid,profile,email` | Comma-separated. `openid` is added if absent. |
| `OIDC_REDIRECT_URL` | `http://localhost:8080/auth/callback` | The shared callback: the provider a sign-in began with rides in the signed state cookie, so one registered redirect URI serves every issuer. Point it at `/auth/callback/oidc:<name>` only for an IdP that insists on a distinct URI per client. |

Login routes: `/auth/login` (defaults to GitHub) and `/auth/login/{provider}`, where
`{provider}` is `github` or `oidc:<name>`. A provider that is not configured answers 400,
so an OIDC-only deployment refuses `/auth/login/github` rather than half-starting a flow. `GET /api/v1/auth/providers` lists what this
deployment has configured; the login page draws its buttons from it.

#### First admin

| Variable | Default | Description |
|----------|---------|-------------|
| `BOOTSTRAP_ADMINS` | `""` | Comma-separated identities promoted to installation admin when they sign in: `github:<subject>` or `oidc:<name>:<subject>`. `<subject>` is the issuer's stable user id — the numeric GitHub user id (`gh api users/<login> --jq .id`), or the OIDC `sub` claim — and may itself contain colons. Matched on (provider, subject) only, never email ([ADR-047](adr/0047-provider-agnostic-identity.md)). A malformed entry fails startup. |

#### Installation policy

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGNUP_MODE` | `open` | `open` creates an account (global role `viewer`) for any identity a configured issuer vouches for — any GitHub account, with GitHub. `existing` signs in only identities that already have an account, plus `BOOTSTRAP_ADMINS`; anyone else gets 401 at the callback. |
| `SELF_SERVICE_NAMESPACES` | `true` | Whether a global `viewer` may create a namespace, either directly or by creating a registry without naming an existing namespace. `false` restricts both to global `member` and `admin` (403 otherwise). |

A private installation usually wants `SIGNUP_MODE=existing` and
`SELF_SERVICE_NAMESPACES=false`; see [DEPLOYMENT.md](DEPLOYMENT.md) "Hardening a private
installation".

Nothing else creates an admin: a fresh install has none, and every new account starts as
`viewer`. Promotion happens at sign-in, so an account can be listed before it exists. It
only ever promotes — an admin demoted by hand is promoted again at their next sign-in until
they are removed from the list.

Signed-in users can link a second issuer to their account from `/admin/account`. A subject
already linked to a different account is refused with 409 — OCIDex never merges accounts —
and so is unlinking an account's last remaining identity.

### Frontend / CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `FRONTEND_URL` | `http://localhost:3000` | Post-login redirect target and CORS default. With `ENVIRONMENT=production` the redirect is this URL exactly. Outside production the redirect follows the login request's hostname with this URL's port — so several dev hostnames work — but only when that origin is in `CORS_ALLOWED_ORIGINS`; any other host falls back to this URL. |
| `CORS_ALLOWED_ORIGINS` | `""` | Comma-separated CORS origins, each a bare `scheme://host[:port]` (no path, not even `/`). Empty falls back to `FRONTEND_URL`. With `ENVIRONMENT=production` a `*` or a malformed entry fails startup; in development `*` is only warned about. The same set decides which origins may send cookie-authenticated writes. |
| `API_BASE_URL` | `""` | Public base URL of the API, used to populate the OpenAPI `servers` block for tooling/docs. Optional. |

### Database Pool

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_MAX_CONNECTIONS` | `10` | pgx connection pool size. Reduce for worker processes (2–5 is typical). |

### Enrichment Pipeline

Controls how SBOMs are enriched after ingestion (OCI label extraction, user metadata).

| Variable | Default | Description |
|----------|---------|-------------|
| `ENRICHMENT_ENABLED` | `true` | Read by the per-enricher workers; gates whether they consume enrichment jobs. Has no effect on the API process. |
| `ENRICHMENT_WORKERS` | `2` | Number of concurrent enrichment goroutines inside each enricher worker process. |
| `ENRICHMENT_QUEUE_SIZE` | `100` | Enrichment work queue depth inside each enricher worker process before back-pressure. |

### OCI Registry Scanner

Controls webhook-triggered and poll-triggered OCI image scanning (runs Syft).

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_ENABLED` | `false` | On the API, enables publishing scan requests (required for both webhook and poll scan modes). The API never scans in-process, so a `scanner-worker` must run to consume the requests. |
| `SCANNER_WORKERS` | `2` | Number of concurrent scan goroutines inside each `scanner-worker` process. |
| `SCANNER_QUEUE_SIZE` | `50` | Scan work queue depth inside each `scanner-worker` process. |
| `SCANNER_MAX_IMAGE_BYTES` | `2147483648` | Largest image the worker hands to Syft, as total *compressed* layer bytes read from its manifest. Above this the job fails permanently without pulling anything — Syft unpacks every layer, so an image past what `limits.memory` can hold OOMKills the container instead of returning an error, taking any concurrent scan with it. Raise this and the memory limit together; `0` disables the check. |
| `SCANNER_GO_SYMBOLS` | `all` | Which Go binary packages get their linked function symbols captured, for symbol-level vulnerability matching ([ADR-050](adr/0050-go-symbol-level-vulnerability-matching.md)): `none`, `stdlib`, `extended-stdlib` or `all`. `all` is needed to filter third-party module advisories, not just the standard library's. A large Go image links ~1M symbols; the scan holds them in memory briefly and ingest stores them deduplicated. |
| `REGISTRY_POLLER_ENABLED` | `false` | Enable the background poller for registries with `scan_mode=poll` or `scan_mode=both`. Requires `SCANNER_ENABLED=true`. Uses leader election so multiple API replicas are safe. |

**Scan mode summary:**

| Registry `scan_mode` | What triggers a scan |
|----------------------|----------------------|
| `webhook` | Registry pushes events to `/api/v1/registries/{id}/webhook` |
| `poll` | Poller periodically lists tags and scans new digests. Requires `SCANNER_ENABLED=true` + `REGISTRY_POLLER_ENABLED=true`. |
| `both` | Both webhook and poll. |

### Credential Encryption

Registry auth tokens and webhook secrets are encrypted in the database with AES-256-GCM
([ADR-051](adr/0051-credential-encryption-at-rest.md)). Set the same values on every process
that loads the main config: the API, `scanner-worker` and the enricher workers.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_ENCRYPTION_KEYS` | `""` | Comma-separated `<id>:<base64 32-byte key>`. Every key listed can decrypt. An id is `[A-Za-z0-9_-]{1,32}`. Generate a key with `openssl rand -base64 32`. **Required when `ENVIRONMENT=production`**; without it, startup fails. Outside production, unset means credentials are stored in plaintext and the API logs a warning. |
| `DATA_ENCRYPTION_ACTIVE_KEY` | `""` | The key id new values are encrypted with. Must name a key in `DATA_ENCRYPTION_KEYS`. |

A malformed key list, a key that is not 32 bytes, or an active id not in the list fails
startup. Rotation and key loss: [OPERATIONS.md](OPERATIONS.md#rotating-the-credential-encryption-key).

### Egress Policy

Registry URLs are user-supplied, so every process that dials them — the API, `scanner-worker`
and the enricher workers — checks the resolved IP of each connection against this policy
(`internal/netguard`). Set the same values on all of them. On the API this includes ingest:
an uploaded container SBOM's image is HEADed at its registry, so an SBOM naming a refused
address is rejected with 400 — including a private registry unless it is allowed here.

| Variable | Default | Description |
|----------|---------|-------------|
| `EGRESS_ALLOW_PRIVATE` | `false` | Allow private addresses: `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT), `fc00::/7`. Needed to scan a registry inside the cluster or LAN; prefer `EGRESS_ALLOW_CIDRS` naming just that host. |
| `EGRESS_ALLOW_CIDRS` | `""` | Comma-separated CIDRs (or bare IPs) always reachable. The only way to reach loopback, link-local (`169.254/16`, including cloud metadata) or multicast, which are otherwise always refused. |
| `EGRESS_DENY_CIDRS` | `""` | Comma-separated CIDRs refused in addition to the built-in ranges, e.g. the cluster's service CIDR when `EGRESS_ALLOW_PRIVATE=true`. An allow entry still wins. |

A malformed CIDR in either list fails startup. `HTTP_PROXY`/`HTTPS_PROXY` are honoured; a
proxied request is checked against the proxy's address, and the proxy's own egress rules apply
to the target.

### Provenance Reverification

Periodically requeues the provenance enrichment job for SBOMs whose last successful check is
older than the configured interval, so drift (a trust config change, or a registry deleting
the artifact) is detected without a new push. Runs on the API process via leader election.

| Variable | Default | Description |
|----------|---------|-------------|
| `PROVENANCE_REVERIFIER_ENABLED` | `true` | Enable the background provenance recheck sweep. Uses leader election so multiple API replicas are safe. |
| `PROVENANCE_RECHECK_INTERVAL` | `24h` | How old a SBOM's last successful provenance check must be before it's requeued. Also controls the sweep's tick rate. |
| `PROVENANCE_TIMEOUT` | `90s` | Bounds one provenance enrichment end to end: the existence HEAD, referrers discovery and its child layer fetches, the Rekor lookup, and cosign verification (which may itself refresh the Sigstore trusted root, allowed 30s of its own). The phases share one budget deliberately — giving each its own would leave total wall clock unbounded across a variable number of child fetches. A mid-chain expiry costs a retry, so raise this when provenance error rates climb against a slow registry. The Rekor lookup is the one exception: it is scoped to 10s of the budget, because it is fail-open and should never be able to starve verification. |
| `PROVENANCE_MAX_LAYER_BYTES` | `16777216` (16MiB) | Read budget for one manifest's signature layers, and separately for one manifest's attestation layers. The layers are registry-controlled and read whole into memory — a bare cosign signature is a few KB, an attestation carrying a full SBOM is megabytes — and reading one unbounded is what OOMKilled the worker. It is a budget shared across a manifest's layers, not a per-layer cap: a `.sig` manifest holds one layer per signature and every one is read, so a per-layer cap would multiply the ceiling by the layer count. A manifest listing more than 32 layers is rejected outright. Exceeding either fails that job with a diagnosable error, not the pod. Raise the worker's memory limit alongside this. |
| `GIT_MAX_RESPONSE_BYTES` | `4194304` (4MiB) | Largest GitHub API response body the git enricher will read. Same reasoning as `PROVENANCE_MAX_LAYER_BYTES`: a remote-controlled body read whole into memory puts the worker's memory limit in someone else's hands. A successful response over the cap fails that job; an oversized *error* body is truncated into the message so the status code is not lost. |

### NATS JetStream

Required by every process — the API and both workers fail to start without `NATS_URL`.

| Variable | Default | Description |
|----------|---------|-------------|
| `NATS_URL` | — | **Required.** NATS server connection URL. |
| `NATS_STREAM_NAME` | `ocidex` | JetStream stream name. |
| `NATS_EVENT_TTL_HOURS` | `24` | How long events are retained in the stream. |
| `NATS_STREAM_REPLICAS` | `1` | JetStream stream replica count. Set to `3` for a 3-node NATS cluster. |

### Audit Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_LOG_ENABLED` | `true` | Emit structured audit log entries for mutating API operations. |

### Metrics

The API serves Prometheus metrics on a separate, private listener (ADR-0054), never on `PORT`.
Don't route it through your ingress.

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ADDR` | `:9090` | Listen address for `/metrics`. Empty disables the listener and metrics. |
| `OTEL_RESOURCE_ATTRIBUTES` | — | Extra resource attributes, e.g. `deployment.environment.name=prod`. They appear on the `target_info` series. |

Request metrics are the `http_server_request_duration_seconds` histogram, labelled
`http_request_method`, `http_route` (the route pattern, such as `/api/v1/sboms/{id}`; `unmatched`
for paths no route serves) and `http_response_status_code`. Its `_count` series is the request
count. Go runtime (`go_*`) and process (`process_*`) metrics are included.

The API, the job workers and `vuln-worker` also report their database pools,
`ocidex_db_pool_connections{pool,state}`, `ocidex_db_pool_acquires_total{pool,outcome}` and
`ocidex_db_pool_acquire_wait_seconds_total{pool}` (`pool` is `main`, or `background` for the API's
out-of-band pool), and binaries that publish to NATS count
`ocidex_nats_publishes_total{subject_class,outcome}` (`ok`, `duplicate`, `error`).

---

## Worker Binaries

All worker binaries require `DATABASE_URL` and `NATS_URL` and will exit non-zero immediately if either is missing.

Every worker, and `k8s-agent`, serves `/healthz`, `/readyz` and Prometheus `/metrics` on `:9090`.
Job workers add `ocidex_jobs_processed_total{queue,outcome}` (`success`, `retry`,
`permanent_failure`), `ocidex_job_duration_seconds{queue}` and the queue-depth gauge
`ocidex_jobs{queue,state}` (`queued`, `running`). `queue` is `scan` or the enricher name
(ADR-0054).

### `scanner-worker`

Runs as a long-lived daemon consuming scan jobs from NATS.

Shares the same config vars as the API process. Relevant subset:

- `DATABASE_URL` (required)
- `NATS_URL`, `NATS_STREAM_NAME` (`NATS_URL` required)
- `SCANNER_WORKERS`, `SCANNER_QUEUE_SIZE`
- `DATABASE_MAX_CONNECTIONS` (set low, e.g. `3`)

**One-shot mode** (`--once` flag): Scans a single image and exits. Useful for K8s Jobs or ad-hoc scanning.

| Variable | Description |
|----------|-------------|
| `SCAN_IMAGE` | **Required.** Full image reference: `registry/repo:tag@sha256:digest` |
| `SCAN_REGISTRY_ID` | Optional UUID of the OCIDex registry record to associate the SBOM with. |
| `SCAN_INSECURE` | `true` to allow HTTP/insecure registries. |
| `SCAN_AUTH_USERNAME` | Registry auth username. |
| `SCAN_AUTH_TOKEN` | Registry auth token/password. |

### Enricher Workers

Each enricher runs as its own long-lived daemon, claiming only the `enrichment_jobs` rows
scoped to its `enricher_name`. Deploy them as independent K8s Deployments to scale and
restart each enricher independently.

All three workers share the same relevant config vars:

- `DATABASE_URL` (required)
- `NATS_URL`, `NATS_STREAM_NAME` (`NATS_URL` required)
- `ENRICHMENT_MAX_CONCURRENCY`, `ENRICHMENT_POLL_INTERVAL`, `ENRICHMENT_STUCK_THRESHOLD`, `ENRICHMENT_MAX_ATTEMPTS`
- `DATABASE_MAX_CONNECTIONS` (set low, e.g. `3`)

**One-shot mode** (`--once` flag): Enriches a single SBOM and exits. Useful for K8s Jobs or ad-hoc re-enrichment.

| Variable | Description |
|----------|-------------|
| `ENRICH_SBOM_ID` | **Required.** UUID of the SBOM to enrich. |

#### `oci-metadata-worker`

Claims `enricher_name='oci-metadata'` rows. Fetches OCI image labels, architecture, and
build metadata from the registry using `go-containerregistry`.

#### `user-enricher-worker`

Claims `enricher_name='user'` rows. Derives enrichment from ingest-time parameters
(version, architecture, build date) supplied by the caller. No outbound network calls.

#### `provenance-worker`

Claims `enricher_name='provenance'` rows. Fetches cosign signatures and SLSA attestations
from the registry via the OCI 1.1 Referrers API (with cosign tag-scheme fallback). When a
registry has a trust anchor configured, delegates verification to cosign (see
[Per-Registry Trust Anchors](#per-registry-trust-anchors) below and ADR-037).

### `vuln-worker`

Matches stored SBOMs against the [grype](https://github.com/anchore/grype) vulnerability
database ([ADR-049](adr/0049-vulnerability-matching-via-grype.md)). Needs `DATABASE_URL`
but not NATS. A Postgres advisory lock makes one replica the leader.

| Variable | Default | Description |
|----------|---------|-------------|
| `VULN_REFRESH_ENABLED` | `true` | Gates the scheduled refresh loop. |
| `VULN_REFRESH_INTERVAL` | `6h` | Minimum time between refreshes. |
| `VULN_DB_DIR` | `/var/lib/ocidex/grype-db` | Where the grype database is installed (~3 GB). An update needs room for the download plus two copies, so give it ~10 GiB. In Kubernetes this is a PVC (`vulnWorker.db.persistence`); use node-local storage, not NFS, because the database is SQLite. |
| `VULN_DB_UPDATE_URL` | grype default | Listing checked for newer databases (`https://grype.anchore.io/databases`). Point it at a self-hosted `grype-db` build to control the source. |
| `VULN_DB_MAX_AGE` | `120h` | Reject a database built longer ago than this. grype publishes daily. |

### `k8s-agent`

The cluster inventory agent (ADR-044). Unlike every other binary here it needs **no
`DATABASE_URL` and no `NATS_URL`** — it runs inside the cluster it reports on, which may have
no OCIDex deployment of its own, and talks only to the OCIDex API over HTTP.

| Variable | Default | Description |
|----------|---------|-------------|
| `OCIDEX_SERVER` | — | **Required.** OCIDex API base URL, e.g. `https://ocidex.example.com`. |
| `OCIDEX_API_KEY` | — | **Required.** API key carrying the `push_inventory` capability, owned by a member whose role on the cluster's namespace grants it. |
| `OCIDEX_CLUSTER_ID` | — | **Required.** UUID of the registered `cluster` this agent reports for. Supplied rather than discovered: a Kubernetes cluster has no stable self-identifier, and a defaulted one could replace the wrong cluster's inventory. |
| `OCIDEX_NAMESPACES` | *(all)* | Comma-separated Kubernetes namespace allowlist. Empty means every namespace. |
| `OCIDEX_REPORT_INTERVAL` | `5m` | Time between snapshots. Ignored under `--once`. |
| `HEALTH_ADDR` | `:9090` | Liveness/readiness listen address (`/healthz`, `/readyz`). |
| `LOG_LEVEL`, `ENVIRONMENT` | `info`, `development` | As elsewhere. |

RBAC: `list`/`watch` on `pods` cluster-wide, and nothing else — workload ownership is resolved
from the pod's own `ownerReferences` and `pod-template-hash` label rather than by reading
ReplicaSets. `charts/ocidex-k8s-agent` ships exactly that ClusterRole; see
[DEPLOYMENT.md § Cluster inventory agent](DEPLOYMENT.md#cluster-inventory-agent-separate-chart-per-target-cluster).

**One-shot mode** (`--once` flag): pushes a single snapshot and exits 0, or exits 1 on
failure. Suitable for a CronJob.

Two behaviours are load-bearing and easy to mistake for bugs:

- **Every push is a complete snapshot.** Workloads the agent does not report are *deleted*
  server-side (ADR-044 K7). Narrowing `OCIDEX_NAMESPACES` on a running agent therefore prunes
  the namespaces it stops reporting; it does not leave them behind as stale rows.
- **An empty snapshot is still pushed.** A cluster running nothing and a cluster whose agent
  has died must not look alike, and `cluster.last_seen_at` is stamped by the push, not by the
  rows (ADR-044 K2).

Images whose digest cannot be read from `status.containerStatuses[].imageID` are reported with
no digest and surface as **unresolvable** rather than being dropped — a missing workload would
read as "nothing is running there". The agent logs an `unresolvable` count on every push.

---

## Per-Registry Trust Anchors

Provenance verification trust is configured **per registry** via the API or admin UI —
there are no environment variables for it. Settings are stored on the registry row.

### `verification_mode`

| Value | Behaviour |
|-------|-----------|
| `none` | Default. No verification attempted; provenance badge shows `signed` when referrers are found. |
| `public_key` | Verify signatures with the registry's PEM public key; badge shows `verified` or `verification_failed`. |
| `keyless` | Verify against Fulcio/Rekor via `sigstore-go`, matching the configured `trust_identity` and `trust_issuer`; badge shows `verified` or `verification_failed`. See [ADR-037](adr/0037-cosign-delegated-provenance-verification.md). |

### `trust_public_key`

PEM-encoded ECDSA P-256 public key used for `public_key` verification. For
`ghcr.io/pfenerty` this is the contents of `apko-cicd/cosign.pub`.

### Signing-status badge values

Five values, defined by `SigningStatus` (`internal/enrichment/provenance/status.go`) and mirrored
by the `signing_status(jsonb)` SQL function. The frontend renders them from a single table,
`web/src/utils/trust.ts`.

| Value | Badge | Meaning |
|-------|-------|---------|
| `verified` | blue | A cryptographic check ran and passed (`public_key` or `keyless`). |
| `signed` | grey | Referrers found; no trust anchor configured (`verification_mode=none`), so nothing was checked. |
| `unsigned` | grey | No signature or attestation referrers found. |
| `artifact_missing` | amber | The digest no longer resolves in the registry, so provenance can't be re-checked. |
| `verification_failed` | red | A check ran and failed, or a referrer payload was present but unparseable (fail-closed). |

The colour axis separates *what OCIDex knows* from *what is wrong*: blue means OCIDex affirmed
something, grey means it has no information, amber is an availability problem, red is a trust
problem. In particular `signed` is deliberately neutral — it reflects an unconfigured trust anchor
on the registry, not a defect in the artifact, and reads as a prompt to set `verification_mode`.
`verification_failed` stays visually distinct from `unsigned` so operators can tell a potentially
tampered image from an unsigned one.

### Admin UI path

**Admin → Registries → Edit → Verification Mode**

Set `Verification Mode` to `public_key` and paste the PEM public key into the
`Trust Public Key` field.

---

## Reference Configs

### Minimal (no scan, no poll)

```env
DATABASE_URL=postgres://ocidex:ocidex@localhost:5432/ocidex?sslmode=disable
NATS_URL=nats://localhost:4222
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
SESSION_SECRET=...
```

### Docker Compose

The bundled `docker-compose.yml` runs the full distributed topology — API,
`scanner-worker`, the per-enricher workers, `vuln-worker`, NATS, Postgres, and a
one-shot `migrate` service — mirroring the Kubernetes layout. The API has scanning off by default;
set `SCANNER_ENABLED=true` to publish scan jobs to the running `scanner-worker`.

```env
DATABASE_URL=postgres://ocidex:ocidex@postgres:5432/ocidex?sslmode=disable
NATS_URL=nats://nats:4222
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
SESSION_SECRET=...
```

### Kubernetes

API process:
```env
DATABASE_URL=...
SCANNER_ENABLED=true
NATS_URL=nats://nats:4222
NATS_STREAM_REPLICAS=3
REGISTRY_POLLER_ENABLED=true
```

`scanner-worker`, `oci-metadata-worker`, `user-enricher-worker`, and `provenance-worker` processes:
```env
DATABASE_URL=...
NATS_URL=nats://nats:4222
NATS_STREAM_REPLICAS=3
DATABASE_MAX_CONNECTIONS=3
```
