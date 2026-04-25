# CLAUDE.md - OCIDex

## Agent Behavior

- Be very concise in your output
- Do not do extra work that was not asked for
- Assume the user is a competent engineer asking for specific functionality — do not over-explain or add unrequested features
- Challenge design decisions when necessary
- After making frontend changes, run `make frontend-lint-fix` to auto-fix ESLint errors, then `make frontend-lint` to verify no remaining issues

## Codebase Exploration with Repomix

Repomix MCP tools are available and auto-allowed. Prefer them over spawning Explore subagents or doing many sequential Glob/Grep calls when you need broad codebase understanding.

```
# Pack the local codebase (call once per session for broad exploration)
mcp__repomix__pack_codebase     → produces an output ID

# Search within a packed output (fast, no re-packing)
mcp__repomix__grep_repomix_output  → regex search across all files

# Read sections of the packed output
mcp__repomix__read_repomix_output  → read with offset/limit

# Attach a previous pack by output ID (avoids re-packing)
mcp__repomix__attach_packed_output
```

**When to use repomix:**
- PR review or security review (pack once, grep many times)
- "How does X work across the codebase?" questions
- Finding all callsites/usages of an interface or function
- Any exploration that would otherwise require 5+ Glob/Grep calls

**When to use Glob/Grep directly:**
- You already know the file or directory
- Single targeted lookup (one file, one symbol)

## Project Overview

OCIDex (Open Container Initiative Dex) is a Go HTTP service for maintaining metadata about software artifacts, particularly SBOMs. It receives CycloneDX JSON SBOMs via API, stores them in a database, maintains links between software artifacts for tracking over time, and provides search by artifact, package/version, and license.

The project uses a layered architecture (API -> Service -> Repository) with dependency injection and interface-based design.

## Tech Stack

- **Language:** Go (module: `github.com/pfenerty/ocidex`)
- **HTTP Router:** [chi](https://github.com/go-chi/chi)
- **Database:** PostgreSQL (driver: pgx, query gen: sqlc, migrations: goose)
- **Frontend:** SolidJS + Vite + Tailwind CSS
- **Testing:** matryer/is (unit), testcontainers-go (integration)
- **Linting:** golangci-lint (configured in `.golangci.yml`)
- **CI:** GitHub Actions (lint, test, build, security scan)
- **Container:** Docker multi-stage build (Alpine)
- **Dev Environment:** Flox

## Flox Environment

Most tools (`go`, `make`, `node`, `npm`, `oras`, `syft`) are only available inside the Flox environment. **All build/test commands must be run through Flox:**

```bash
# Correct — always wrap with flox activate
flox activate -- bash -c 'export PATH="$HOME/go/bin:$PATH"; make check'
flox activate -- bash -c 'export PATH="$HOME/go/bin:$PATH"; make test'
flox activate -- bash -c 'export PATH="$HOME/go/bin:$PATH"; make lint'
flox activate -- bash -c 'export PATH="$HOME/go/bin:$PATH"; make build'
flox activate -- bash -c 'export PATH="$HOME/go/bin:$PATH"; make generate'

# For simple commands that don't need ~/go/bin tools:
flox activate -- make fmt
flox activate -- make migrate-up
flox activate -- make frontend-dev
```

**Why `bash -c` with PATH?** `golangci-lint` and `sqlc` are installed via `go install` into `~/go/bin/`, which isn't on PATH by default inside Flox. Commands that invoke these tools (`make lint`, `make check`, `make generate`) need the PATH export.

Exceptions:
- `goose` is installed globally at `~/.local/bin/goose`
- `docker` is NOT available in this environment
- `sqlc` and `golangci-lint` require `flox activate -- make init` (or `go install`) first

## Key Commands

```bash
make run               # Run the application
make build             # Build the binary to bin/
make fmt               # Format code with gofmt
make lint              # Run golangci-lint
make test              # Run unit tests (race detector enabled)
make test-coverage     # Run tests with HTML coverage report
make test-integration  # Run integration tests from tests/
make check             # Run fmt + lint + test
make init              # Download deps and install tools
make clean             # Clean build artifacts
make generate          # Run sqlc code generation
make openapi           # Regenerate OpenAPI spec + frontend TypeScript types
make migrate-up        # Run database migrations up
make migrate-down      # Roll back last database migration
make seed              # Seed database with real SBOMs
make frontend          # Build the SolidJS frontend
make frontend-dev      # Start frontend dev server (proxies API to :8080)
make frontend-lint     # Run ESLint on the SolidJS frontend
make frontend-lint-fix # Run ESLint with auto-fix on the SolidJS frontend
make tekton-synth      # Synthesize Tekton pipeline YAML from TypeScript
make tekton-check      # Verify generated Tekton YAML is up-to-date
```

## Project Structure

```
cmd/ocidex/            # API server entry point
cmd/scanner-worker/    # OCI registry scanner worker
cmd/enrichment-worker/ # SBOM enrichment worker
cmd/specgen/           # OpenAPI spec generator
internal/api/          # HTTP handlers and routing (chi + huma)
internal/config/       # Configuration management (caarlos0/env)
internal/repository/   # Data access layer (sqlc-generated + models)
internal/service/      # Business logic
internal/enrichment/   # SBOM enrichment pipeline
internal/scanner/      # OCI registry scanning
internal/nats/         # NATS JetStream integration
internal/event/        # In-process event bus
internal/extension/    # Extension lifecycle management
internal/audit/        # Audit logging
db/migrations/         # goose SQL migrations
db/queries/            # sqlc SQL queries (source of truth for repository layer)
web/                   # SolidJS frontend (Vite + Tailwind)
docker/                # Multi-stage Dockerfiles (api, web)
k8s/                   # Kubernetes manifests
config/                # Configuration templates (zot registry)
scripts/               # Utility scripts (seed.nu)
tests/                 # Integration tests (testcontainers)
.tekton/               # Tekton CI pipeline (tektonic TypeScript → generated YAML)
docs/adr/              # Architecture Decision Records (see summary below)
docs/DEVELOPMENT.md    # Coding patterns and examples
```

## Generated Files

`internal/repository/*sql.go` and `internal/repository/models.go` are **generated by sqlc**. Do not edit them directly. Instead:

1. Edit the SQL in `db/queries/*.sql`
2. Run `make generate` (or `sqlc generate`)
3. The `internal/repository/` files will be regenerated

`web/openapi.json` and `web/src/types/openapi.d.ts` are **generated from the Go API types**. Whenever you add, remove, or change fields on any type in `internal/api/types.go` (or change routes/methods in `internal/api/router.go`), run:

```bash
flox activate -- make openapi
```

This regenerates `web/openapi.json` (via `cmd/specgen`) and `web/src/types/openapi.d.ts` (via `openapi-typescript`). The frontend TypeScript compiler enforces the generated types, so stale types cause Docker build failures.

## Database Workflow

- **Migrations:** `db/migrations/` managed by goose. Use `make migrate-up` / `make migrate-down`.
- **Queries:** `db/queries/*.sql` with sqlc annotations. Run `make generate` after changes.
- **Connection:** Configured via `DATABASE_URL` env var.

## Frontend

- **Framework:** SolidJS (not React — no virtual DOM, fine-grained reactivity)
- **Build:** Vite (`make frontend` to build, `make frontend-dev` for dev server)
- **API proxy:** Dev server proxies `/api/*` to `localhost:8080`
- **Styling:** Tailwind CSS

## Code Conventions

- Standard Go project layout (`cmd/`, `internal/`, `pkg/`)
- Explicit error handling; propagate errors up, handle at boundaries
- Use `context.Context` for cancellation and deadlines
- Table-driven tests
- Document all exported functions and types
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Cyclomatic complexity limit: 15

## Configuration

Environment variables (see `.env.example`):
- `PORT` (default: 8080)
- `LOG_LEVEL` (default: info)
- `ENVIRONMENT` (development/staging/production)
- `DATABASE_URL` (PostgreSQL connection string)

## Health Endpoints

- `GET /health` - Liveness check
- `GET /ready` - Readiness check

## Architecture Principles

- Layered architecture: API -> Service -> Repository
- Dependency injection via constructors
- Program to interfaces for testability
- Fail fast: validate config and dependencies at startup
- Graceful shutdown with 30-second timeout
- Prefer small, composable, idiomatic libraries over large batteries-included frameworks

## Issue Tracking (Beads)

This project uses [Beads](https://github.com/steveyegge/beads) (`bd`) for task tracking. **Do NOT use TodoWrite or TaskCreate** — use `bd` instead.

The session-start hook auto-runs `bd prime` when `.beads/` is present. Run it manually after compaction or `/clear`.

**Roadmap structure** (epics established for the path to 1.0):

| Epic | Theme |
|---|---|
| `ocidex-6ce` | 1.0 — Solid Core (refactor + stabilize) |
| `ocidex-ars` | 1.1 — Production K8s deployment |
| `ocidex-utt` | 1.2 — CLI tool (`cmd/ocidex-cli`) |
| `ocidex-m4x` | 1.3 — K8s operator + CRDs |
| `ocidex-4o0` | 1.4 — Terraform provider |

The 1.0 epic has 36 child tasks (`ocidex-6ce.1` through `.36`) organized into sections A–H. See the plan at `~/.claude/plans/this-app-started-as-validated-star.md`.

**Workflow:**

```bash
bd ready                              # Find unblocked work
bd ready --priority=1                 # Top-priority ready work
bd show <id>                          # Inspect an issue
git checkout main && git pull         # Start from latest main
git checkout -b <branch-name>         # New branch per issue
bd update <id> --status=in_progress   # Claim it before coding
bd close <id>                         # Close on completion
bd close <id1> <id2> ...              # Close multiple at once
```

**Conventions:**
- Create the issue *before* writing code; mark `in_progress` when starting.
- Always branch from `main` before starting work on an issue (`git checkout main && git pull && git checkout -b <branch-name>`).
- Priority is `0`–`4` (or `P0`–`P4`), where `0` is critical. Don't use `high`/`medium`/`low`.
- Hierarchical IDs (`<epic>.<n>`) come from the `--parent` flag at create time.
- Cross-issue dependencies via `bd dep add <issue> <depends-on>`.
- **Never** use `bd edit` — it opens `$EDITOR` and blocks. Use `bd update --title/--description/--notes` instead.
- Beads auto-commits its database to Dolt; run `git push` at session end to push code changes.

## ADR Summary

| # | Decision | Choice |
|---|----------|--------|
| 002 | HTTP Router | chi |
| 003 | Structured Logging | log/slog |
| 004 | Configuration | caarlos0/env |
| 005 | Database Engine | PostgreSQL |
| 006 | Database Access | sqlc + pgx |
| 007 | Schema Migrations | goose |
| 008 | Input Validation | Custom validation for CycloneDX |
| 009 | Error Handling | stdlib errors + custom API error types |
| 010 | Testing | matryer/is (unit) + testcontainers (integration) |
| 011 | API Documentation | ~~oapi-codegen (spec-first)~~ superseded by 018 |
| 012 | Frontend Framework | SolidJS |
| 013 | State/Routing/Data | Collocated data fetching near components |
| 014 | Build/Deploy | Vite; independent API/frontend deploys |
| 015 | UI/Styling | Accessible components, WCAG 2.1 AA |
| 016 | Frontend Testing | Table-driven parity with backend |
| 017 | Frontend Organization | Monorepo; single `make build` |
| 018 | API Documentation | huma v2 (code-first, supersedes 011) |
