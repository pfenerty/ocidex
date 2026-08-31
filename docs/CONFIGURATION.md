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

Signed-in users can link a second issuer to their account from `/admin/account`. A subject
already linked to a different account is refused with 409 — OCIDex never merges accounts —
and so is unlinking an account's last remaining identity.

### Frontend / CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `FRONTEND_URL` | `http://localhost:3000` | Post-login redirect target and CORS default. Only the port matters — hostname is derived from the login request. |
| `CORS_ALLOWED_ORIGINS` | `""` | Comma-separated CORS origins. Must NOT be `*` when credentials are involved. Should match `FRONTEND_URL`. |
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
| `REGISTRY_POLLER_ENABLED` | `false` | Enable the background poller for registries with `scan_mode=poll` or `scan_mode=both`. Requires `SCANNER_ENABLED=true`. Uses leader election so multiple API replicas are safe. |

**Scan mode summary:**

| Registry `scan_mode` | What triggers a scan |
|----------------------|----------------------|
| `webhook` | Registry pushes events to `/api/v1/registries/{id}/webhook` |
| `poll` | Poller periodically lists tags and scans new digests. Requires `SCANNER_ENABLED=true` + `REGISTRY_POLLER_ENABLED=true`. |
| `both` | Both webhook and poll. |

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

---

## Worker Binaries

All worker binaries require `DATABASE_URL` and `NATS_URL` and will exit non-zero immediately if either is missing.

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
