# Architecture

Technical overview of OCIDex's design. For coding patterns and examples, see [DEVELOPMENT.md](DEVELOPMENT.md). For the rationale behind specific technology choices, see the [ADRs](adr/).

## System Overview

OCIDex is a set of processes around one PostgreSQL database. The API is the only process that
serves users. Every slow or external step runs in a worker that claims jobs from a table in
Postgres, so nothing waits on a registry, a scan or an advisory feed while a request is open.

```
Browser, ocidex-cli, ocidex-mcp (stdio), CI, operator (CRDs), k8s-agent
        │
        ▼
ingress ──── everything but /api, /auth, /health, /ready ───▶ web (nginx: the SPA)
        │
        ▼
┌────────────────────────────────────────────────────────────┐
│ api (cmd/ocidex)                                           │
│   chi + huma handlers → services → sqlc repository         │
│   background: rollup refresher, session cleaner,           │
│   provenance reverifier, retention sweep (one replica)     │
└────────────────────────────────────────────────────────────┘
        │ rows (sboms, scan_jobs, enrichment_jobs)        │ hints
        ▼                                                 ▼
┌──────────────────────────────────┐    ┌────────────────────────────────┐
│ PostgreSQL                       │    │ NATS JetStream                 │
│   the catalog and every job row  │    │   "a job row is waiting"       │
│   (the source of truth)          │    │   (a lost hint costs a poll)   │
└──────────────────────────────────┘    └────────────────────────────────┘
        ▲ claim jobs, write results,       │ wake the scanner and
        │ ingest SBOMs                     ▼ enricher workers
┌──────────────────────┐  ┌──────────────────────┐  ┌────────────────────┐
│ scanner-worker       │  │ enricher workers     │  │ vuln-worker        │
│   catalog walks,     │  │   one per enricher:  │  │   grype DB refresh │
│   syft scans, ingest │  │   oci-metadata, git, │  │   and re-match     │
└──────────────────────┘  │   user, provenance   │  │   (one replica)    │
                          └──────────────────────┘  └────────────────────┘
        │                         │
        ▼                         ▼
OCI registries            registries, GitHub, Rekor
(all outbound traffic goes through the egress policy)

migrate Job: `ocidex migrate up`, before the API rolls out (Helm pre-install/upgrade hook)
```

The processes, all built from this repository:

| Process | Binary | What it does |
|---|---|---|
| API | `cmd/ocidex` | REST API under `/api/v1`, sign-in under `/auth`. Ingests uploaded SBOMs, cluster inventory and registry webhooks. Runs the rollup refresher, session cleaner, provenance reverifier and, on one replica at a time, the retention sweep (ADR-0056). |
| Web | `docker/web` (nginx) | Serves the SolidJS SPA (ADR-038). The ingress routes `/api`, `/auth`, `/health` and `/ready` to the API and everything else here. |
| NATS JetStream | upstream image | Carries hints that a job row exists. The job rows in Postgres are the source of truth (ADR-024). |
| scanner-worker | `cmd/scanner-worker` | Walks registry catalogs, runs syft on each selected image and ingests the SBOM (ADR-031). |
| Enricher workers | `cmd/oci-metadata-worker`, `cmd/git-worker`, `cmd/user-enricher-worker`, `cmd/provenance-worker` | One Deployment per enricher, each claiming only the `enrichment_jobs` rows with its `enricher_name` (ADR-033). |
| vuln-worker | `cmd/vuln-worker` | Keeps the package-keyed vulnerability store current against the grype database (ADR-049). |
| migrate Job | `cmd/ocidex migrate up` | Applies the embedded goose migrations. The API never migrates on startup. |
| Operator | `cmd/operator` | Optional, separate chart. Reconciles `OCIRegistry`, `ScanRequest` and `APIKey` CRDs through the API (ADR-030). |
| k8s-agent | `cmd/k8s-agent` | Runs in each inventoried cluster and pushes what it runs to the API (ADR-044). |
| MCP server | `cmd/ocidex-mcp` | A local stdio server an agent launches. It calls the API with the user's key and is never deployed (ADR-045). |
| CLI | `cmd/ocidex-cli` | Ingest, query and key management against the API. |

### Request paths

- **Read.** Browser → web → API → services → repository → Postgres. Every read is filtered by the
  caller's visibility (ADR-046). Expensive aggregates come from rollup tables that the API's
  rollup refresher rebuilds in the background, not from joins at request time.
- **Ingest.** An SBOM arrives by upload (`POST /api/v1/sboms`), from the scanner-worker, or from the
  CLI or MCP server. Ingest stores it and its components in one transaction, then writes one
  `enrichment_jobs` row per enricher and publishes a hint for each.
- **Scan.** A catalog walk (on a schedule, a webhook, a `ScanRequest` or a cluster's running images
  under ADR-0044 K10) writes `scan_jobs` rows and publishes hints. A scanner-worker claims a row,
  pulls the image through the egress policy, runs syft, and ingests the result as above.
- **Enrich.** Each enricher worker claims its rows, reads what it needs from the registry, the git
  host or Rekor, and stores its result in `enrichment`, keyed by `(sbom_id, enricher_name)`.
- **Vulnerabilities.** The vuln-worker matches components against the grype database and stores
  matches keyed by package URL, so a new advisory reaches every affected SBOM without a rescan.
- **Cluster inventory.** A k8s-agent pushes a full snapshot. The API replaces that cluster's
  workloads in one transaction, then queues scans for running images with no SBOM (ADR-0044).

Within the API, every request follows the same path: **Router → Handler → Service → Repository →
Database**. No layer is skipped, and dependencies only point downward.

## Layered Architecture

OCIDex uses a strict three-layer architecture with dependency injection at each boundary.

### API Layer (`internal/api/`)

HTTP handlers registered with [huma](https://huma.rocks/) on a [chi](https://github.com/go-chi/chi) router. Responsibilities:

- Request parsing, validation (via huma struct tags), and content negotiation
- Calling service methods with the request context
- Mapping service results to HTTP responses
- Error translation via RFC 7807 problem details (provided by huma)

Handlers use huma's typed signature pattern:

```go
func (h *Handler) GetArtifact(ctx context.Context, input *GetArtifactInput) (*GetArtifactOutput, error)
```

This replaces the raw `func(w, r)` pattern. Huma handles JSON encoding, status codes, and error responses automatically.

### Service Layer (`internal/service/`)

Business logic that is independent of HTTP. Each domain area (artifacts, SBOMs, components, licenses, diff) has an interface and a concrete implementation. Responsibilities:

- Orchestrating repository calls (e.g., ingesting an SBOM involves inserting the SBOM, its components, and its dependency edges in a transaction)
- Domain-specific validation beyond what the API layer checks
- Computing derived data (changelogs, diffs, license summaries)
- Publishing events after SBOM ingestion, which the enrichment submitter turns into job rows

Services accept repository interfaces via constructors, making them testable with fakes.

### Repository Layer (`internal/repository/`)

Data access generated by [sqlc](https://sqlc.dev/). The SQL in `db/queries/*.sql` is the source of truth — running `make generate` produces Go code that is type-safe and requires no manual editing.

Responsibilities:

- CRUD operations against PostgreSQL
- Transaction management (via `pgx` pool)
- Mapping database rows to Go structs

**Important:** Files in `internal/repository/` ending in `_sql.go` and `models.go` are generated. Edit the SQL in `db/queries/`, not the Go code.

## Data Model

The core entities and their relationships:

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   Artifact   │ 1───* │     SBOM     │ 1───* │  Component   │
│              │       │              │       │              │
│ id           │       │ id           │       │ id           │
│ name         │       │ artifact_id  │       │ sbom_id      │
│ group        │       │ spec_version │       │ name         │
│ type         │       │ version      │       │ group        │
│ purl         │       │ serial_number│       │ version      │
│ cpe          │       │ digest       │       │ type         │
│ created_at   │       │ subject_ver  │       │ purl         │
└──────────────┘       │ build_date   │       │ bom_ref      │
                       │ raw_bom      │       │ scope        │
                       │ created_at   │       └──────┬───────┘
                       └──────┬───────┘              │
                              │                      │ *───*
                              │               ┌──────┴───────┐
                              │               │  Dependency   │
                              │               │  (join table) │
                              │               │ from_ref      │
                              │               │ to_ref        │
                              │               └──────────────┘
                              │
                         1───*│
                       ┌──────┴───────┐       ┌──────────────┐
                       │  Enrichment  │       │   License    │
                       │              │       │              │
                       │ sbom_id      │       │ id           │
                       │ enricher_name│       │ name         │
                       │ status       │       │ spdx_id      │
                       │ data (JSONB) │       │ category     │
                       │ error_message│       │ url          │
                       └──────────────┘       └──────────────┘
                                                    │
                                               *───*│ (via component_licenses)
                                              Component
```

### Key relationships

- **Artifact → SBOM**: One artifact has many SBOMs over time. Each SBOM represents a point-in-time snapshot.
- **SBOM → Component**: An SBOM contains many components. Components belong to exactly one SBOM (they are not deduplicated across SBOMs).
- **Component → Component (dependencies)**: The dependency graph is stored as directed edges between bom-refs within a single SBOM.
- **Component → License**: Many-to-many via a join table. Licenses are deduplicated globally by SPDX ID.
- **SBOM → Enrichment**: Each SBOM can have multiple enrichment results (one per enricher). Stored as JSONB for schema flexibility.

### Why components are per-SBOM

Components are not deduplicated across SBOMs. The same library appearing in two SBOMs creates two component rows. This is deliberate:

1. It preserves the exact content of each SBOM as ingested
2. It makes changelog computation straightforward (diff two component sets)
3. It avoids complex versioning logic at the data layer
4. Deduplication for search is handled at query time and in rollup tables the API refreshes in the background

## API Design

### Code-first OpenAPI

The API spec is generated from Go struct types at startup using [huma v2](https://huma.rocks/). There is no hand-written OpenAPI YAML. This means:

- The spec is always accurate — it IS the code
- Input validation is declared via struct tags and enforced automatically
- The interactive docs UI the API serves at `/docs` is always up to date. The chart's ingress routes only `/api`, `/auth`, `/health` and `/ready` to the API, so reach it on the API's Service or a local run

The generated spec is also exported to `web/openapi.json` for frontend type generation (see [Frontend Architecture](#frontend-architecture)).

### Conventions

- **Pagination**: List endpoints accept `limit` and `offset` query parameters and return a `pagination` object with `{ limit, offset, total }`.
- **Errors**: All errors use [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) problem details: `{ type, title, status, detail, errors[] }`. This is provided automatically by huma.
- **IDs**: UUIDs for all entities, generated server-side.
- **Versioning**: All endpoints are under `/api/v1`.

## Frontend Architecture

The frontend is a SolidJS single-page application in `web/`.

### Stack

- **SolidJS** — Fine-grained reactivity via signals. No virtual DOM. Components render once; only the reactive expressions within them update. ([ADR-012](adr/0012-frontend-framework.md))
- **TanStack Query** (solid-query) — Server state management with caching, background refetching, and loading/error states.
- **openapi-fetch** — Type-safe HTTP client generated from the OpenAPI spec. Request/response types are inferred from the spec, so the frontend stays in sync with the backend at compile time.
- **Tailwind CSS** — Utility-first styling.
- **Vite** — Build tooling and dev server with API proxy.

### Data flow

```
OpenAPI spec (web/openapi.json)
    │
    ▼  openapi-typescript (codegen)
src/types/openapi.d.ts          ← generated TypeScript types
    │
    ▼  imported by
src/api/client.ts               ← openapi-fetch client + APIClientError
    │
    ▼  used by
src/api/queries/*.ts            ← TanStack Query hooks (one file per domain)
    │                              - wraps client calls in queryFn
    │                              - normalizes nullable arrays via select
    │                              - provides enabled/staleTime options
    ▼  consumed by
src/pages/*.tsx                 ← page components (route-level)
    │
    ▼  render
src/components/*.tsx            ← shared UI components (Feedback, Pagination, etc.)
```

The query hooks in `src/api/queries/` are the boundary between the API and the UI. Pages never call `client.GET(...)` directly. This means:

- API response transformations (like null coalescing) happen in one place
- Query keys and caching behavior are centralized
- Pages are testable without an HTTP client

### Key patterns

- **Nullable array normalization**: OpenAPI codegen types arrays as `T[] | null`. Query hooks use TanStack Query's `select` option to coalesce these to `T[]`, so pages never deal with null arrays.
- **Structural prop types**: Sub-components accept resolved data, not query result objects. Loading, error, and empty states are handled by the parent using SolidJS `<Show>` guards.
- **View-layer formatting**: Display formatting functions (`artifactDisplayName`, `relativeDate`, etc.) live in `src/utils/` and are applied by page components, not by query hooks.

## Enrichment Pipeline

Enrichment runs outside the API, in one worker Deployment per enricher (ADR-033). Ingest never
waits for it.

### How it works

1. When an SBOM is committed, an extension on the in-process event bus writes one
   `enrichment_jobs` row per enricher and publishes a NATS hint for each (ADR-024, ADR-033).
2. Each enricher worker claims rows with its own `enricher_name`, from a hint or from its poll
   loop. The poll loop is what makes a lost hint cost seconds, not a job.
3. The enricher checks `CanEnrich(ref)`. If the subject is relevant, it does its work and returns
   JSON.
4. The result is upserted into `enrichment` as JSONB, keyed by `(sbom_id, enricher_name)`, and the
   job row is finished. A failure is retried up to its attempt budget, then left `failed` for the
   Jobs page and its Retry button.

```
ingest commits ──▶ enrichment_jobs (one row per enricher) ──▶ NATS hint
                          │
          ┌───────────────┼────────────────┬──────────────────┐
          ▼               ▼                ▼                  ▼
   oci-metadata-worker  git-worker  user-enricher-worker  provenance-worker
          │               │                │                  │
          └───────────────┴──── enrichment (JSONB) ───────────┘
```

### Enrichers

| Enricher | Worker | Adds |
|---|---|---|
| `oci-metadata` | `oci-metadata-worker` | Image labels, architecture, OS, build time and source URLs from the registry. |
| `git` | `git-worker` | The source commit, fetched from GitHub using the revision and source URL `oci-metadata` found. |
| `user` | `user-enricher-worker` | Metadata supplied at upload, with no network call. |
| `provenance` | `provenance-worker` | Signatures and attestations, verified against the configured trust policy. |

Vulnerability matching is not an enricher. The vuln-worker matches components against a package-keyed
store, so a newly published advisory reaches every affected SBOM without re-enriching it (ADR-049).

### Design decisions

- **Async, non-blocking.** Ingest returns as soon as its transaction commits. Enrichment happens
  afterwards, in other processes.
- **The database is the queue.** Job rows are the source of truth, and NATS only says one is
  waiting. A dropped hint, a restarted worker or a NATS outage delays work and never loses it.
- **Idempotent.** Results are upserted, so re-enriching an SBOM overwrites its previous result.
- **Independently scaled.** Each enricher is its own Deployment. KEDA can scale each on its own
  queue depth.
- **Extensible.** A new enricher implements the `Enricher` interface (`Name`, `CanEnrich`, `Enrich`)
  and gets its own worker binary and Deployment.

## Database

### Migrations

Schema changes are managed by [goose](https://pressly.github.io/goose/) with SQL migration files in `db/migrations/`. Migrations are explicit: run `ocidex migrate up` (or `make migrate-up`). The API server does not migrate on startup — in multi-replica deployments, K8s runs `ocidex migrate up` as a one-shot Job before rolling the API.

### Query generation

All database queries are defined in `db/queries/*.sql` using sqlc annotations. Running `make generate` produces type-safe Go code in `internal/repository/`. This approach:

- Eliminates hand-written SQL string concatenation
- Catches query errors at code generation time, not runtime
- Produces Go functions with properly typed parameters and return values
- Keeps the SQL visible and reviewable (no ORM magic)

### Connection management

The application uses `pgxpool` for connection pooling. The pool is created once at startup and injected into the repository layer. Graceful shutdown drains the pool after the HTTP server stops accepting connections.

## Deployment

### Images and chart

Each process ships as its own image, built from `docker/Dockerfile` (one target per Go binary) and
`docker/web/Dockerfile` (nginx and the SPA). The Go images are distroless and the web image is Chainguard
nginx. All run as non-root and carry their license texts under `/licenses` (ADR-038). The Helm chart in `charts/ocidex` deploys
the API, web, NATS, scanner-worker, enricher workers and vuln-worker, plus the migrate Job. The
operator has its own chart. Topology and values are in [DEPLOYMENT.md](DEPLOYMENT.md).

`docker-compose.yml` runs the same set locally: PostgreSQL, NATS, the migrate step, the API, the
scanner-worker, every enricher worker, the vuln-worker and the web tier.

### Configuration

All configuration is via environment variables, parsed at startup using
[caarlos0/env](https://github.com/caarlos0/env). The server fails fast if a required variable (like
`DATABASE_URL`) is missing, with no silent defaults for critical config. Every variable is listed in
[CONFIGURATION.md](CONFIGURATION.md).

### Health checks

- `GET /health` — Liveness: returns 200 if the process is running
- `GET /ready` — Readiness: returns 200 if the database connection is healthy

Workers serve `/healthz` and `/readyz` on their metrics port (9090) instead. Kubernetes uses both
kinds of probe.
