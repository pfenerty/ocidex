# Configuration Reference

OCIDex is configured entirely via environment variables. The API server, scanner worker, and enrichment worker all share the same `Config` struct (`internal/config/config.go`) and load from the process environment.

## Deployment Modes

OCIDex supports two deployment topologies, controlled by a single `OCIDEX_MODE` variable:

### Embedded (default — Docker Compose / single server)

All subsystems run inside the single `ocidex` process. No NATS or separate workers needed.

```
┌─────────────────────────────────────────────────────────┐
│  ocidex API process                                       │
│  ├── HTTP server                                          │
│  ├── Enrichment workers  (ENRICHMENT_ENABLED=true)       │
│  ├── Scanner workers     (SCANNER_ENABLED=true)           │
│  └── Registry poller     (REGISTRY_POLLER_ENABLED=true)  │
└─────────────────────────────────────────────────────────┘
```

Key setting: `OCIDEX_MODE=embedded` (or unset — this is the default)

### Distributed (Kubernetes / production)

The API process publishes work to NATS JetStream; separate worker processes consume it. Run `scanner-worker` and `enrichment-worker` as independent deployments.

```
┌──────────────────┐     ┌─────────┐     ┌──────────────────┐
│  ocidex API      │────▶│  NATS   │────▶│  scanner-worker  │
│  (publishes jobs)│     │JetStream│     │  enrichment-     │
│  + registry poll │     └─────────┘     │  worker          │
└──────────────────┘                     └──────────────────┘
```

Key setting: `OCIDEX_MODE=distributed` (requires `NATS_URL`)

---

## Environment Variables

### Core

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `DATABASE_URL` | — | **yes** | PostgreSQL connection string. Migrations run automatically at startup. |
| `PORT` | `8080` | no | HTTP listen port. |
| `LOG_LEVEL` | `info` | no | Log verbosity: `debug`, `info`, `warn`, `error`. |
| `ENVIRONMENT` | `development` | no | Runtime environment label: `development`, `staging`, `production`. |
| `OCIDEX_MODE` | `embedded` | no | Deployment mode. `embedded`: in-process enrichment and scanning, no NATS required. `distributed`: NATS required; API publishes, workers consume from JetStream. |

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
| `ENRICHMENT_ENABLED` | `true` | Enable in-process enrichment workers. Only applies in `embedded` mode; ignored in `distributed` mode (enrichment-worker handles it). |
| `ENRICHMENT_WORKERS` | `2` | Number of concurrent in-process enrichment goroutines. |
| `ENRICHMENT_QUEUE_SIZE` | `100` | In-process enrichment work queue depth before back-pressure. |

### OCI Registry Scanner

Controls webhook-triggered and poll-triggered OCI image scanning (runs Syft).

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_ENABLED` | `false` | Enable the scanner subsystem. Required for both webhook and poll scan modes. |
| `SCANNER_WORKERS` | `2` | Number of concurrent in-process scan goroutines. Only used in `embedded` mode. |
| `SCANNER_QUEUE_SIZE` | `50` | In-process scan work queue depth. Only used in `embedded` mode. |
| `REGISTRY_POLLER_ENABLED` | `false` | Enable the background poller for registries with `scan_mode=poll` or `scan_mode=both`. Requires `SCANNER_ENABLED=true`. Uses leader election so multiple API replicas are safe. |

**Scan mode summary:**

| Registry `scan_mode` | What triggers a scan |
|----------------------|----------------------|
| `webhook` | Registry pushes events to `/api/v1/registries/{id}/webhook` |
| `poll` | Poller periodically lists tags and scans new digests. Requires `SCANNER_ENABLED=true` + `REGISTRY_POLLER_ENABLED=true`. |
| `both` | Both webhook and poll. |

### NATS JetStream

Required when `OCIDEX_MODE=distributed`. Ignored in `embedded` mode.

| Variable | Default | Description |
|----------|---------|-------------|
| `NATS_URL` | `nats://localhost:4222` | NATS server connection URL. |
| `NATS_STREAM_NAME` | `ocidex` | JetStream stream name. |
| `NATS_EVENT_TTL_HOURS` | `24` | How long events are retained in the stream. |
| `NATS_STREAM_REPLICAS` | `1` | JetStream stream replica count. Set to `3` for a 3-node NATS cluster. |

### Audit Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_LOG_ENABLED` | `true` | Emit structured audit log entries for mutating API operations. |

---

## Worker Binaries

Both worker binaries require `OCIDEX_MODE=distributed` and will exit non-zero immediately if it is not set.

### `scanner-worker`

Runs as a long-lived daemon consuming scan jobs from NATS.

Shares the same config vars as the API process. Relevant subset:

- `DATABASE_URL` (required)
- `OCIDEX_MODE=distributed`
- `NATS_URL`, `NATS_STREAM_NAME`
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
- `OCIDEX_MODE=distributed`
- `NATS_URL`, `NATS_STREAM_NAME`
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
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
SESSION_SECRET=...
```

### Docker Compose (in-process scan + poll)

```env
DATABASE_URL=postgres://ocidex:ocidex@postgres:5432/ocidex?sslmode=disable
SCANNER_ENABLED=true
REGISTRY_POLLER_ENABLED=true
ENRICHMENT_ENABLED=true
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
SESSION_SECRET=...
```

### Kubernetes (distributed mode)

API process:
```env
DATABASE_URL=...
OCIDEX_MODE=distributed
SCANNER_ENABLED=true
NATS_URL=nats://nats:4222
NATS_STREAM_REPLICAS=3
REGISTRY_POLLER_ENABLED=true
```

`scanner-worker` and `enrichment-worker` processes:
```env
DATABASE_URL=...
OCIDEX_MODE=distributed
NATS_URL=nats://nats:4222
NATS_STREAM_REPLICAS=3
DATABASE_MAX_CONNECTIONS=3
```
