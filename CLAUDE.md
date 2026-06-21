# CLAUDE.md - OCIDex

## Agent Behavior

- Be very concise in your output
- Do not do extra work that was not asked for
- Assume the user is a competent engineer asking for specific functionality — do not over-explain or add unrequested features
- Challenge design decisions when necessary
- After making frontend changes, run `make frontend-lint-fix` to auto-fix ESLint errors, then `make frontend-lint` to verify no remaining issues

## Codebase Exploration with Repomix

Repomix is available two ways — prefer MCP tools when loaded; fall back to the CLI (available in the flox environment) otherwise.

**MCP tools** (auto-allowed when the MCP server is active):
```
mcp__repomix__pack_codebase        → pack codebase, produces an output ID
mcp__repomix__grep_repomix_output  → regex search within a packed output
mcp__repomix__read_repomix_output  → read sections with offset/limit
mcp__repomix__attach_packed_output → reattach a previous pack by ID
```

**CLI fallback** (when MCP tools are not loaded in the session):
```bash
# Pack and write to repomix-output.xml (gitignored)
flox activate -- repomix

# Pack a subtree only
flox activate -- repomix internal/service

# Search the output file directly
grep -n "pattern" repomix-output.xml
```

**When to use repomix (either form):**
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
- `goose` (DB migrations) lives at `~/go/bin/goose` — installed via `go install github.com/pressly/goose/v3/cmd/goose@latest`. **Do not use `~/.local/bin/goose`** — that path is the unrelated goose AI agent tool.
- `make migrate-up` / `make migrate-down` call `goose` by name. If they fail because the wrong binary is found, run the migration directly: `~/go/bin/goose -dir db/migrations postgres "$(grep DATABASE_URL /home/patrick/code/ocidex/.env | cut -d= -f2-)" up`
- `DATABASE_URL` must be set in the shell or read from `.env`; it is not exported automatically.
- `docker` is NOT available in this environment
- `sqlc`, `golangci-lint`, and `controller-gen` require `flox activate -- make init` (or `go install`) first
- `golangci-lint` v2 is required (config uses v2 format). The flox environment includes v2; `make init` installs `github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`.
- `controller-gen` lives at `~/go/bin/controller-gen` — installed via `go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest`. Targets that invoke it (`make generate-operator`) need the PATH export.

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
make generate-operator # Regenerate CRD manifests and deepcopy (controller-gen)
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
make dev-cluster-up    # Create local Talos dev cluster + registry (one-time per session)
make dev-up            # Tilt: build, deploy, watch the stack on the local cluster
make dev-down          # Stop Tilt
make dev-cluster-down  # Destroy the local Talos cluster and registry
```

## Tekton CI Dev Loop

**Never push commits just to test a pipeline change.** Edit task YAML directly and apply it to the cluster, then create an isolated TaskRun. This turns a 1-hour iteration into ~2 minutes.

### Fast iteration on a single task

```bash
# 1. Edit the task YAML
vim .tekton/tasks/gh-release.k8s.yaml

# 2. Apply directly to the cluster — no commit, no PAC cycle
# The ocidex-ci namespace is labeled to bypass the Tekton admission webhook:
#   kubectl label namespace ocidex-ci webhooks.knative.dev/exclude=true
# Without this label, kubectl apply fails with "non-existent variable" for any $VAR in scripts.
kubectl apply -f .tekton/tasks/gh-release.k8s.yaml

# 3. Find a reusable workspace PVC from a recent pipeline run
kubectl get pvc -n ocidex-ci

# 4. Create an isolated TaskRun (edit params/PVC name as needed)
kubectl apply -f - <<'EOF'
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  generateName: test-gh-release-
  namespace: ocidex-ci
spec:
  taskRef:
    name: ocidex-gh-release
  params:
    - name: repo-full-name
      value: pfenerty/ocidex
    - name: revision
      value: <sha>
    - name: source-branch
      value: refs/tags/v0.0.1-rc.2
  workspaces:
    - name: workspace
      persistentVolumeClaim:
        claimName: <pvc-from-recent-run>
EOF

# 5. Watch logs
kubectl logs -n ocidex-ci -l tekton.dev/taskRun=<name> -f --all-containers
```

The workspace PVC from any recent push or tag run already has the source cloned — reuse it directly. PVCs persist after the run completes until Tekton's pruning kicks in (max 5 runs per `max-keep-runs`).

### Triggering a full pipeline without a commit

Re-push the current tag to trigger the tag pipeline, or push an empty commit to trigger the push pipeline:

```bash
# Re-trigger tag pipeline (no code change needed)
git push origin :v0.0.1-rc.2 && git push origin v0.0.1-rc.2

# Trigger push pipeline
git commit --allow-empty -m "chore: retrigger CI" && git push
```

### Watching pipeline progress

```bash
kubectl get pipelinerun -n ocidex-ci --sort-by=.metadata.creationTimestamp | tail -5
kubectl get taskrun -n ocidex-ci --sort-by=.metadata.creationTimestamp | grep <pr-name>
kubectl logs -n ocidex-ci -l tekton.dev/taskRun=<taskrun-name> -f --all-containers
```

### Known gotchas

| Symptom | Cause | Fix |
|---------|-------|-----|
| `secret-created: false` on PipelineRun | PAC GitHub App missing `Checks: read/write` | Add permission in GitHub App settings |
| `CreateContainerConfigError` on task pod | Referenced secret doesn't exist in cluster | Verify secret with `kubectl get secret -n ocidex-ci`; ensure Flux has reconciled |
| `refs/tags/v0.0.1-rc.2` appearing as image tag or release name | PAC sets `source_branch` to the full ref for tag events | Strip prefix: `TAG="${TAG#refs/tags/}"` after reading `$(params.source-branch)` |
| `403 Forbidden` pulling `ghcr.io/<other-org>/image` | Cluster's `ghcr-docker-config` only covers `pfenerty/*` | Use images from `ghcr.io/pfenerty/apko-cicd/*` or Docker Hub instead |
| Image release task shows `Succeeded` but image wasn't pushed | `onError: continue` masks step failures — TaskRun shows Succeeded even if buildctl failed | Check step logs directly; don't trust TaskRun status alone for `onError: continue` steps |

### Shell variable syntax in task scripts

Tekton's admission webhook flags `$VAR` and `${VAR}` patterns in scripts as undeclared Tekton params — even when they're plain shell variables. The webhook is bypassed for the `ocidex-ci` namespace (see above), but this affects:

- **What to write**: Use `$VAR` (no braces) for simple references. For parameter expansion operators (`${VAR#prefix}`, `${VAR%suffix}`), use POSIX `sed` equivalents: `VAR=$(echo "$VAR" | sed 's|^prefix||')`.
- **`ec` and exit-code files**: Write `echo "$ec"` not `echo "${ec}"`.
- **The output line for buildctl**: Use `"name=${NAMES}"` — this is the one place where `${NAMES}` is required by buildctl's flag syntax and is exempt because it's inside a quoted arg, not a standalone variable reference.

### tektonic synthesis bug

`make tekton-synth` silently drops certain shell parameter expansion patterns (e.g. `${VAR#prefix}`) from generated YAML — a cdk8s/js-yaml serialization issue with `#` inside block scalars. Until fixed:

1. Make the change in `.tektonic/pipeline.ts` (source of truth)
2. Edit the generated `.tekton/tasks/*.yaml` directly to match
3. Apply with `kubectl apply -f .tekton/tasks/<changed>.k8s.yaml` to validate immediately

## Local K8s dev loop (Talos + Tilt)

`make dev-cluster-up` provisions a Docker-backed Talos cluster (`talosctl cluster create`) wired
to a local Docker registry on `localhost:5005`. `make dev-up` runs Tilt, which builds the API/worker
image, pushes to the local registry, and applies `k8s/overlays/dev`. The frontend is served by Vite
locally (port 3000) for HMR; the API is port-forwarded from the cluster on 8080. Tilt UI: `:10350`.

The Talos registry-mirror config (`tilt/talos-cluster.yaml`) makes pods inside the cluster pull
`localhost:5005/...` from the host's bridge IP `10.5.0.1`. `tilt`, `talosctl`, and `kubectl`
are pinned in Flox — run these commands inside `flox activate`. `docker` is a host requirement.

## Project Structure

```
cmd/ocidex/            # API server entry point
cmd/scanner-worker/    # OCI registry scanner worker
cmd/enrichment-worker/ # SBOM enrichment worker
cmd/operator/          # K8s operator entry point (ocidex-01v)
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
api/v1alpha1/          # K8s CRD types (OCIRegistry, ScanRequest, APIKey) — generated deepcopy
k8s/                   # Kubernetes manifests
config/operator/       # CRD install manifests + RBAC (controller-gen output; do not edit)
config/zot/            # Configuration templates (zot registry)
scripts/               # Utility scripts (seed.nu)
tests/                 # Integration tests (testcontainers)
.tekton/               # Tekton CI pipeline (tektonic TypeScript → generated YAML)
docs/adr/              # Architecture Decision Records (see summary below)
docs/DEVELOPMENT.md    # Coding patterns and examples
docs/SBOM_DIFF.md      # User guide: diff views, identity rules, flavor axis, troubleshooting
```

## Generated Files

`api/v1alpha1/zz_generated.deepcopy.go` and `config/operator/crd/*.yaml` are **generated by controller-gen**. Do not edit them directly. Instead:

1. Edit the types in `api/v1alpha1/*_types.go`
2. Run `make generate-operator` (requires `~/go/bin` in PATH)
3. Commit both the type files and the regenerated output

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
- TDD: write failing test, then implement. For diff/tree code specifically,
  see [docs/DEVELOPMENT.md § Testing diff/tree changes](docs/DEVELOPMENT.md#testing-difftree-changes) — codifies parity rule, ADR-contract testing, and the round-trip integration-test requirement.

## Configuration

Environment variables (see `.env.example` and `docs/CONFIGURATION.md`):
- `PORT` (default: 8080)
- `LOG_LEVEL` (default: info)
- `ENVIRONMENT` (development/staging/production)
- `DATABASE_URL` (PostgreSQL connection string)
- `NATS_URL` (required) — NATS JetStream URL. The deployment is distributed-only: the API publishes scan/enrich jobs and `scanner-worker`/`enrichment-worker` consume them. All three binaries (and Docker Compose) require NATS. Migrations are applied explicitly via `ocidex migrate up`, not at startup.

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

**Roadmap structure** (epics for the path to 1.0 and beyond):

| Epic | Theme |
|---|---|
| `ocidex-ujj` | 1.0 — Solid Core (refactor + stabilize) |
| `ocidex-0my` | 1.1 — Production K8s deployment |
| `ocidex-e3g` | 1.2 — CLI tool (`cmd/ocidex-cli`) |
| `ocidex-01v` | 1.3 — K8s operator + CRDs |
| `ocidex-dsy` | 1.4 — Terraform provider |

Verify epic IDs with `bd list --type=epic`; child IDs with `bd show <epic>`.

**Workflow:**

```bash
bd ready                              # Find unblocked work
bd ready --priority=1                 # Top-priority ready work
bd show <id>                          # Inspect an issue
git checkout main && git pull         # Start from latest main
git checkout -b <branch-name>         # New branch per issue
bd update <id> --status=in_progress   # Claim it before coding
# → explore codebase with repomix before implementing (see "Codebase Exploration with Repomix")
# → implement the change
git add <changed files>               # Stage only the relevant files
git commit -m "feat/fix: description (<issue-id>)"  # Commit before closing
bd update <id> --notes "Files: ...\nApproach: ..."  # Document implementation
bd close <id>                         # Close AFTER committing
bd close <id1> <id2> ...              # Close multiple at once
bd close <id> --reason "..."          # Close with a brief one-liner (simple changes only)
```

**Conventions:**
- Create the issue *before* writing code; mark `in_progress` when starting.
- Always branch from `main` before starting work on an issue (`git checkout main && git pull && git checkout -b <branch-name>`).
- **Commit code before closing the issue.** `bd close` without a prior `git commit` leaves changes stranded. The commit message should include the issue ID (e.g. `feat(tekton): add release tasks (ocidex-avi)`).
- Priority is `0`–`4` (or `P0`–`P4`), where `0` is critical. Don't use `high`/`medium`/`low`.
- Hierarchical IDs (`<epic>.<n>`) come from the `--parent` flag at create time.
- Cross-issue dependencies via `bd dep add <issue> <depends-on>`.
- **Never** use `bd edit` — it opens `$EDITOR` and blocks. Use `bd update --title/--description/--notes` instead.
- Before closing an issue, always record how it was resolved: `bd update <id> --notes "Files: <key files>\nApproach: <what was done and why>"`. For trivial changes, `bd close <id> --reason "..."` is sufficient. Never close without recording something.
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
| 015 | UI/Styling | Tailwind + lucide-solid + unovis + custom primitives (Kobalte/TanStack Table not adopted) |
| 016 | Frontend Testing | Vitest + Solid Testing Library (Playwright/MSW not adopted; no E2E suite yet) |
| 017 | Frontend Organization | Monorepo; single `make build` |
| 018 | API Documentation | huma v2 (code-first, supersedes 011) |
| 019 | Diff Identity Model | Layered: purl-base + identity-bearing qualifiers, tuple fallback, versioned-name post-pass with survivor guard |
| 020 | Image Flavor Axis | Layered SBOM-content detection (OS metadata → purl fingerprint → tag suffix); persisted on `sbom.flavor` |
| 021 | Backend-Computed Diff Tree | Enrich `DiffTree` response with `roots`, `isDirect`, `direction`, `nodeRef`, `descendantChanges`; frontend renders only |
| 023 | Visual Identity | Field-guide / entry-card component conventions |
| 024 | Outbox Pattern for Scan Queue | Postgres-as-queue, NATS-as-doorbell; generic worker in `internal/jobqueue` |
| 025 | RBAC / Visibility Model | Registry owner, public/private visibility, API key scopes (read/write) |
| 026 | Pluggable Enricher Interface | `Enricher` interface (`Name/CanEnrich/Enrich`), `Dispatcher`, registration at startup |
| 027 | Ephemeral Job Contract | `--once` flag for K8s Job mode; env vars, exit codes, structured lifecycle logs |

**When working on diff, dependency-tree, or changelog code, read ADRs 0019–0021 first.** They are the normative contract; the implementation issues (`ocidex-bqh.*`) reference them by section.

**When adding a new API handler,** follow the huma v2 pattern: `huma.Register(api, huma.Operation{...}, handler)` with typed input/output structs; see `docs/DEVELOPMENT.md` and `internal/api/sbom.go`.

**When adding a new enricher,** implement `enrichment.Enricher` and register in `cmd/enrichment-worker/main.go`; see ADR 026 and `docs/DEVELOPMENT.md` "Adding a New Enricher".


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
