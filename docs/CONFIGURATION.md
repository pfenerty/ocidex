# Configuration Reference

OCIDex is configured entirely via environment variables. The API server, scanner worker, and enrichment worker all share the same `Config` struct (`internal/config/config.go`) and load from the process environment.

## Architecture

OCIDex runs as three independent processes wired together by NATS JetStream.
The API process publishes work; the workers consume it. `NATS_URL` is required
for every process — there is no in-process/single-binary mode.

```
┌──────────────────┐     ┌─────────┐     ┌──────────────────┐
│  ocidex API      │────▶│  NATS   │────▶│  scanner-worker  │
│  (publishes jobs)│     │JetStream│     │  enrichment-     │
│  + registry poll │     └─────────┘     │  worker          │
└──────────────────┘                     └──────────────────┘
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

Both worker binaries require `DATABASE_URL` and `NATS_URL` and will exit non-zero immediately if either is missing.

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

### `enrichment-worker`

Runs as a long-lived daemon consuming enrichment jobs from NATS.

Relevant config vars:

- `DATABASE_URL` (required)
- `NATS_URL`, `NATS_STREAM_NAME` (`NATS_URL` required)
- `ENRICHMENT_WORKERS`, `ENRICHMENT_QUEUE_SIZE`
- `DATABASE_MAX_CONNECTIONS` (set low, e.g. `3`)

**One-shot mode** (`--once` flag):

| Variable | Description |
|----------|-------------|
| `ENRICH_SBOM_ID` | **Required.** UUID of the SBOM to enrich. |

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

`scanner-worker` and `enrichment-worker` processes:
```env
DATABASE_URL=...
NATS_URL=nats://nats:4222
NATS_STREAM_REPLICAS=3
DATABASE_MAX_CONNECTIONS=3
```
