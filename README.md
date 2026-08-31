# OCIDex

**A metadata catalog for your software supply chain.**

OCIDex ingests [CycloneDX](https://cyclonedx.org/) SBOMs, links them to the software artifacts they describe, and gives you a searchable inventory of every component, version, and license across your entire portfolio — with a changelog that shows exactly what changed between releases.

<!-- Screenshots: replace these paths with your actual captures -->

<p align="center">
  <img src="docs/screenshots/artifact.png" alt="OCIDex dashboard showing artifact list" width="800" />
</p>

<p align="center">
  <img src="docs/screenshots/changelog.png" alt="Changelog of the image over time" width="800" />
</p>

<p align="center">
  <img src="docs/screenshots/package.png" alt="Details for a particular package" width="800" />
</p>

---

## Features

- **SBOM Ingestion** — POST a CycloneDX JSON document and OCIDex validates, parses, and stores it with full component and dependency graph data.
- **Artifact Tracking** — SBOMs are grouped by artifact (container image, library, application). Browse the full version history of any artifact.
- **Changelog** — See exactly which components were added, removed, or changed between any two SBOMs for an artifact.
- **SBOM Diffing** — Pick any two SBOMs across any artifacts and compare them side by side.
- **Component Search** — Find any package by name, group, or type across all ingested SBOMs. See which artifacts use it and how many versions exist.
- **License Inventory** — Every license found across your SBOMs in one place, categorized as permissive, weak-copyleft, or copyleft, with per-artifact summaries.
- **Enrichment Pipeline** — After ingestion, background workers enrich SBOMs with additional data. The built-in OCI metadata enricher pulls image labels, architecture, and build info directly from container registries.
- **OpenAPI Documentation** — The API spec is generated from code at startup via [huma](https://huma.rocks/). Browse it at `/docs`.

## Quick Start

### With Docker Compose

The fastest way to get a running instance with seed data:

```sh
git clone https://github.com/pfenerty/ocidex.git
cd ocidex
cp .env.example .env   # fill in GitHub OAuth credentials and SESSION_SECRET
docker compose up -d
```

This starts PostgreSQL, NATS JetStream, the OCIDex API server (port 8080), the scanner and enrichment workers, and the web frontend (port 3000). Database migrations run automatically on startup.

Then open [http://localhost:3000](http://localhost:3000).

To populate it with real-world SBOMs from public container images, log in with GitHub, create an
API key under **Settings → API Keys**, and run the seeder:

```sh
export OCIDEX_API_KEY=ocidex_...
flox activate -- make seed
```

This registers a set of well-annotated public repositories from quay.io and ghcr.io and triggers
a scan on each. It exits once the first artifacts appear; the remaining images continue scanning
in the background.

### From Source

OCIDex uses [Flox](https://flox.dev/) to manage its development environment (Go, Node, npm, oras, syft, and other tools).

```sh
git clone https://github.com/pfenerty/ocidex.git
cd ocidex
flox activate

# Install Go tools (golangci-lint, oapi-codegen, controller-gen)
make init

# Start PostgreSQL and NATS (via docker-compose, or provide your own)
docker compose up -d postgres nats

# Configure — SESSION_SECRET is always required, plus at least one identity
# provider: GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET, or OIDC_ISSUER_URL +
# OIDC_CLIENT_ID, or both. Edit DATABASE_URL / NATS_URL if needed
cp .env.example .env

# Run migrations and build
make migrate-up
make build
make frontend

# Start the server
make run
```

`.env` is read by docker-compose and by the make targets, which export it before running
anything. The binaries themselves read only the process environment — so `./bin/ocidex` invoked
directly ignores `.env` and exits on the required variables. Export them first if you want to run
it outside `make`:

```sh
set -a; . ./.env; set +a
./bin/ocidex
```

The API serves on `:8080` by default. For frontend development with hot reload:

```sh
make frontend-dev   # Vite dev server on :3000, proxies /api/* to :8080
```

### Installing the CLI

`ocidex-cli` is the command-line client for the API — `registry`, `sbom`, `artifact`,
`component`, `job` and `key` subcommands, plus `login`. It ships two ways, and building the repo
is not one of them:

```sh
# With a Go toolchain
go install github.com/pfenerty/ocidex/cmd/ocidex-cli@latest
ocidex-cli version

# Without one
docker run --rm ghcr.io/pfenerty/ocidex-cli:main --help
```

A `go install`ed binary carries no `-ldflags`, so `ocidex-cli version` reports the module version
and VCS stamps the toolchain embedded instead; the published image reports the CI-injected
version. Point it at a server with `OCIDEX_URL` and authenticate with `OCIDEX_API_KEY`, or run
`ocidex-cli login` to write `~/.config/ocidex/config.yaml`. See
[ADR-029](docs/adr/0029-cli-design.md) for the full configuration precedence and exit codes.

### Connecting an Agent

`ocidex-mcp` serves the catalog to MCP clients over stdio, reusing the credentials
`ocidex-cli login` already wrote:

```sh
go install github.com/pfenerty/ocidex/cmd/ocidex-mcp@latest
claude mcp add ocidex -- ocidex-mcp
```

Fourteen tools cover lookup, diff, changelog, vulnerabilities and ingest. See the
[MCP Server guide](docs/MCP.md) for the full list, client configuration and troubleshooting.

### Ingest Your First SBOM

Generate an SBOM with [syft](https://github.com/anchore/syft) and send it to OCIDex:

```sh
syft registry:docker.io/library/nginx:latest -o cyclonedx-json | \
  curl -X POST http://localhost:8080/api/v1/sbom \
    -H "Content-Type: application/json" \
    -d @-
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go |
| HTTP | [chi](https://github.com/go-chi/chi) + [huma](https://huma.rocks/) (code-first OpenAPI 3.1) |
| Database | PostgreSQL ([pgx](https://github.com/jackc/pgx) driver, [sqlc](https://sqlc.dev/) query gen, [goose](https://pressly.github.io/goose/) migrations) |
| Messaging | [NATS JetStream](https://docs.nats.io/nats-concepts/jetstream) (scan and enrichment job queue) |
| Frontend | [SolidJS](https://www.solidjs.com/) + [TanStack Query](https://tanstack.com/query) + [Tailwind CSS](https://tailwindcss.com/) |
| API Client | [openapi-fetch](https://openapi-ts.dev/openapi-fetch/) with generated TypeScript types |
| Testing | [matryer/is](https://github.com/matryer/is) (unit), [testcontainers-go](https://golang.testcontainers.org/) (integration) |
| Container | Docker multi-stage build — [distroless](https://github.com/GoogleContainerTools/distroless) `static-debian13` for Go, [Chainguard](https://www.chainguard.dev/) nginx for the web tier ([ADR-038](docs/adr/0038-web-serving-and-base-image-policy.md)) |
| Dev Environment | [Flox](https://flox.dev/) |

## Project Structure

```
cmd/ocidex/              API server entry point, wiring, graceful shutdown
cmd/scanner-worker/      OCI registry scanner (NATS daemon + --once K8s Job mode)
cmd/oci-metadata-worker/ Per-enricher workers, one per enrichment_jobs partition
cmd/git-worker/          (NATS daemon + --once K8s Job mode; see ADR-033)
cmd/user-enricher-worker/
cmd/provenance-worker/
cmd/vuln-worker/         Scheduled OSV.dev vulnerability store refresher
internal/api/            HTTP handlers and routing (chi + huma)
internal/service/        Business logic interfaces and implementations
internal/repository/     Data access layer (sqlc-generated queries)
internal/enrichment/     Pluggable enrichment pipeline
internal/scanner/        OCI registry scanning (Syft engine)
internal/nats/           NATS JetStream client helpers
internal/jobqueue/       Generic outbox-pattern worker (Postgres → NATS doorbell)
internal/config/         Environment-based configuration
db/migrations/           SQL schema migrations (goose)
db/queries/              SQL query definitions (sqlc source of truth)
web/                     SolidJS frontend (Vite + Tailwind)
tests/                   Integration tests (testcontainers)
charts/                  Helm charts (ocidex, ocidex-operator)
docs/                    Architecture docs, ADRs, development guide
```

## API Overview

All endpoints are under `/api/v1`. The full OpenAPI spec is served at `/openapi.json` and an interactive docs UI at `/docs`.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/sbom` | Ingest a CycloneDX JSON SBOM |
| `GET` | `/api/v1/sbom` | List SBOMs (paginated, filterable) |
| `GET` | `/api/v1/sbom/{id}` | Get SBOM detail |
| `GET` | `/api/v1/sbom/{id}/components` | List components in an SBOM |
| `GET` | `/api/v1/sbom/{id}/dependencies` | Get dependency graph |
| `GET` | `/api/v1/artifacts` | List tracked artifacts |
| `GET` | `/api/v1/artifacts/{id}` | Get artifact detail |
| `GET` | `/api/v1/artifacts/{id}/sboms` | List SBOMs for an artifact |
| `GET` | `/api/v1/artifacts/{id}/changelog` | Get changelog between SBOMs |
| `GET` | `/api/v1/artifacts/{id}/license-summary` | License breakdown for latest SBOM |
| `GET` | `/api/v1/components` | Search components |
| `GET` | `/api/v1/components/distinct` | Deduplicated component search |
| `GET` | `/api/v1/licenses` | List all licenses |
| `GET` | `/api/v1/diff` | Diff any two SBOMs |

Errors follow [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) problem details format.

## Configuration

OCIDex is configured via environment variables:

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full reference. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string (required) |
| `NATS_URL` | — | NATS server URL (required for API + both workers) |
| `PORT` | `8080` | HTTP listen port (API server) |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `ENVIRONMENT` | `development` | Runtime environment |
| `GITHUB_CLIENT_ID` | — | GitHub OAuth app client ID (set with the secret, or leave both unset) |
| `GITHUB_CLIENT_SECRET` | — | GitHub OAuth app client secret |
| `OIDC_ISSUER_URL` | — | OIDC discovery base; enables the generic OIDC provider |
| `SESSION_SECRET` | — | Session signing key (always required; generate with `openssl rand -hex 32`) |
| `FRONTEND_URL` | `http://localhost:3000` | Frontend origin (used for CORS and OAuth redirect) |
| `NATS_STREAM_NAME` | `ocidex` | JetStream stream name |
| `SCANNER_MAX_CONCURRENCY` | `10` | Max parallel scans per scanner-worker pod |
| `ENRICHMENT_MAX_CONCURRENCY` | `10` | Max parallel enrichments per enricher worker pod |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design, data model, and component overview |
| [Development Guide](docs/DEVELOPMENT.md) | Coding patterns, testing strategy, and stack examples |
| [Configuration](docs/CONFIGURATION.md) | All environment variables with descriptions and defaults |
| [Deployment](docs/DEPLOYMENT.md) | Production deployment guide (K8s + Flux) |
| [Ephemeral Jobs](docs/EPHEMERAL_JOBS.md) | K8s Job / `--once` mode for scanner and enrichment workers |
| [MCP Server](docs/MCP.md) | Serving the catalog to agents over stdio: setup, tools, troubleshooting |
| [API Versioning](docs/API_VERSIONING.md) | Versioning policy and breaking-change definition |
| [Frontend Development](docs/FRONTEND_DEV.md) | Dev rigs, browser verification, contract tests |
| [Tekton CI](docs/CI_TEKTON.md) | Fast pipeline iteration, gotchas, task script syntax |
| [Architecture Decision Records](docs/adr/) | 43 ADRs documenting every major technical choice |
| [How AI Was Used](docs/AI.md) | Transparent account of AI's role in development |

## Releases

OCIDex follows [semantic versioning](https://semver.org/). See [CHANGELOG.md](CHANGELOG.md) for the per-version history (generated by [git-cliff](https://git-cliff.org) from conventional commits).

To cut a new release from `main`:

```sh
make release VERSION=v0.1.0
git push origin main v0.1.0
```

The release workflow (`.github/workflows/release.yml`) then builds multi-arch (linux/amd64, linux/arm64) container images for `api`, `scanner-worker`, the per-enricher workers, `vuln-worker`, and `web`, pushes them to `ghcr.io/pfenerty/ocidex-*` tagged with the semver version (plus `latest` for stable releases), and creates a GitHub Release with the changelog as the body. Images carry the standard `org.opencontainers.image.*` annotations and binaries embed their build version (`ocidex --version`).

## Supply chain security

Every published image (`ghcr.io/pfenerty/ocidex-*`) carries build provenance and an SBOM, and
is signed by Tekton Chains (cosign + public Rekor). See
**[docs/verifying-artifacts.md](docs/verifying-artifacts.md)** for copy-paste verification, and
[`cosign.pub`](cosign.pub) for the signing key:

```bash
cosign verify --key cosign.pub ghcr.io/pfenerty/ocidex-api@sha256:<digest>
```

## AI Acknowledgment

This project was built with significant AI assistance (Claude). Architecture decisions, technology selection, and code review are human-driven; implementation, refactoring, and documentation are collaborative. See [How AI Was Used](docs/AI.md) for the full picture.

## License

[MIT](LICENSE)
