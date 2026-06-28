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

### Authentication (GitHub OAuth)

All three vars are required. The app will refuse to start without them.

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_CLIENT_ID` | — | GitHub OAuth App client ID. |
| `GITHUB_CLIENT_SECRET` | — | GitHub OAuth App client secret. |
| `SESSION_SECRET` | — | Cookie signing key. Min 32 bytes. Generate with: `openssl rand -hex 32` |
| `GITHUB_REDIRECT_URL` | `http://localhost:8080/auth/callback` | OAuth callback URL. Must be registered in the GitHub OAuth App. When accessed via a non-localhost address (Tailscale, remote IP), set to that address. |
| `SESSION_MAX_AGE_DAYS` | `7` | How long login sessions last. |

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
| `ENRICHMENT_ENABLED` | `true` | Read by `enrichment-worker`; gates whether it consumes enrichment jobs. Has no effect on the API process. |
| `ENRICHMENT_WORKERS` | `2` | Number of concurrent enrichment goroutines inside each `enrichment-worker` process. |
| `ENRICHMENT_QUEUE_SIZE` | `100` | Enrichment work queue depth inside each `enrichment-worker` process before back-pressure. |

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
registry has a PEM trust anchor configured, performs native ECDSA verification (see
[Per-Registry Trust Anchors](#per-registry-trust-anchors) below).

### `enrichment-worker` (legacy)

The monolithic `enrichment-worker` (claims `enricher_name='all'`) is retained during the
transition period. It runs all three enrichers in one process. Remove it from your
deployment once the three per-enricher workers are stable in production.

---

## Per-Registry Trust Anchors

Provenance verification trust is configured **per registry** via the API or admin UI —
there are no environment variables for it. Settings are stored on the registry row.

### `verification_mode`

| Value | Behaviour |
|-------|-----------|
| `none` | Default. No verification attempted; provenance badge shows `signed` when referrers are found. |
| `public_key` | Verify signatures with the registry's PEM public key; badge shows `verified` or `verification_failed`. |
| `keyless` | Reserved for future Fulcio/sigstore-go support. Currently a no-op (treated as `none`). |

### `trust_public_key`

PEM-encoded ECDSA P-256 public key used for `public_key` verification. For
`ghcr.io/pfenerty` this is the contents of `apko-cicd/cosign.pub`.

### Signing-status badge values

| Value | Meaning |
|-------|---------|
| `unsigned` | No signature or attestation referrers found. |
| `signed` | Referrers found; no trust anchor configured (`verification_mode=none`). |
| `verified` | ECDSA verification passed against the registry's PEM anchor. |
| `verification_failed` | Anchor present but verification failed, or an attestation payload was present but unparseable. |

`verification_failed` is displayed as a danger badge — distinct from `unsigned` — so
operators can distinguish a potentially tampered image from an unsigned one.

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
`scanner-worker`, `enrichment-worker`, NATS, Postgres, and a one-shot `migrate`
service — mirroring the Kubernetes layout. The API has scanning off by default;
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
