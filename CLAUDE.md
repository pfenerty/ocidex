# CLAUDE.md - OCIDex

## Agent Behavior

- Be very concise in your output
- Do not do extra work that was not asked for
- Assume the user is a competent engineer asking for specific functionality — do not over-explain or add unrequested features
- Challenge design decisions when necessary

## Hard Rules

These are the mistakes that cost real time. Everything else is convention.

| Rule | Why / how |
|---|---|
| **Never hand-edit `.tekton/*.yaml`** | Generated from `.tektonic/` by `make tekton-synth`. The `tekton-check` PR task re-synthesizes and fails the PR if `.tekton` comes out dirty. |
| **Never hand-edit `internal/repository/*sql.go` or `models.go`** | sqlc output. Edit `db/queries/*.sql`, then `make generate`. |
| **Never hand-edit `web/openapi.json` or `web/src/types/openapi.d.ts`** | Generated from `internal/api/types.go` + `router.go`. Run `make openapi` after any API type or route change — stale types fail the Docker build. |
| **Never hand-edit `api/v1alpha1/zz_generated.deepcopy.go` or `config/operator/crd/*.yaml`** | controller-gen output. Edit `api/v1alpha1/*_types.go`, then `make generate-operator`. |
| **Never test a pipeline change by pushing a commit** | Apply the task YAML to the cluster and run an isolated TaskRun — ~2 min instead of ~1 h. See [docs/CI_TEKTON.md](docs/CI_TEKTON.md). |
| **Never ship a UI change you have not looked at** | A dead class name or unfetched font passes Vitest. See [docs/FRONTEND_DEV.md](docs/FRONTEND_DEV.md). |
| **Never use `bd edit`** | It opens `$EDITOR` and blocks. Use `bd update --title/--description/--notes`. |
| **Never use TodoWrite, TaskCreate, or markdown TODO lists** | Use `bd`. |
| After a frontend change | `make frontend-lint-fix`, then `make frontend-lint` |
| `docker` is not available in this environment | The Talos/Tilt loop needs it on the host; the auth rig ([docs/FRONTEND_DEV.md](docs/FRONTEND_DEV.md)) does not. |

## Environment

Most tools (`go`, `make`, `node`, `npm`, `oras`, `syft`, `tilt`, `talosctl`, `kubectl`) exist
only inside the Flox environment. Every build/test command goes through it:

```bash
flox activate -- make fmt
flox activate -- make help          # every target, self-documented — use this, not a list here
```

`golangci-lint`, `sqlc`, and `controller-gen` are installed by `make init` into `~/go/bin`, which
is **not** on PATH inside Flox. Targets that invoke them (`lint`, `check`, `generate`,
`generate-operator`) need the export:

```bash
flox activate -- bash -c 'export PATH="$HOME/go/bin:$PATH"; make check'
```

Two gotchas:

- `DATABASE_URL` is exported for **make targets** only (the Makefile does `include .env` +
  `export`). Running a binary directly does not read `.env` — do `set -a; . ./.env; set +a`.
- `make migrate-up` / `migrate-down` run `go run ./cmd/ocidex migrate up|down` with migrations
  embedded. There is no `goose` CLI; `~/.local/bin/goose` is an unrelated tool.

## Codebase Exploration

`~/.claude/CLAUDE.md` already mandates tokensave-first and bans Explore agents. The ocidex
specifics:

- **tokensave** is a pre-built code graph, not a text search — use it for "where is X defined",
  callers/callees, impact radius, symbol bodies. For planning a story, call
  `tokensave_context(task=..., mode="plan")` **first**; it surfaces extension points and
  dependency order. If a call errors, `tokensave_status`, then
  `tokensave wipe && tokensave init && tokensave install`.
- **repomix** only when tokensave doesn't answer — broad, non-symbol-shaped review
  (e.g. auditing all of `.tekton/tasks/`).
- **headroom** to compress any tool output over ~2k tokens before it lands in context.
- **`Read`/`Grep`** for files you're about to edit, single targeted lookups, and non-code content
  (prose, YAML, config).

Soft budget: ~15 research calls before falling back to `AskUserQuestion` — a proxy for "this
needs human input, not more searching."

## Project Overview

OCIDex (Open Container Initiative Dex) is a Go HTTP service for maintaining metadata about
software artifacts, particularly SBOMs. It receives CycloneDX JSON SBOMs via API, stores them,
maintains links between artifacts for tracking over time, and provides search by artifact,
package/version, and license.

- **Language:** Go (`github.com/pfenerty/ocidex`) — chi + huma v2, pgx + sqlc, goose migrations
- **Database:** PostgreSQL
- **Frontend:** SolidJS + Vite + Tailwind
- **Messaging:** NATS JetStream (required — the deployment is distributed-only)
- **Testing:** matryer/is (unit), testcontainers-go (integration), Vitest (frontend)
- **Images:** Chainguard nginx for the web tier, distroless static-debian13 for Go (ADR-038)
- **CI:** Tekton Pipelines-as-Code — see [docs/CI_TEKTON.md](docs/CI_TEKTON.md)

Layered architecture: API → Service → Repository, dependency-injected via constructors, each
layer importing only the one below. Full design in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
cmd/ocidex/            # API server entry point (also `migrate` subcommand)
cmd/scanner-worker/    # OCI registry scanner worker
cmd/*-worker/          # One binary per enricher, partitioned by
                       # enrichment_jobs.enricher_name (ADR-033):
                       # oci-metadata, git, user-enricher, provenance, vuln
cmd/ocidex-mcp/        # Stdio MCP server for agents (ADR-045)
cmd/operator/          # K8s operator entry point
cmd/specgen/           # OpenAPI spec generator
internal/api/          # HTTP handlers and routing (chi + huma)
internal/service/      # Business logic
internal/repository/   # Data access (sqlc-generated + models)
internal/enrichment/   # SBOM enrichment pipeline (deps.go = the enricher graph)
internal/scanner/      # OCI registry scanning
internal/nats/         # NATS JetStream integration
internal/jobqueue/     # Generic outbox worker (ADR-024)
db/migrations/         # goose SQL migrations
db/queries/            # sqlc SQL queries — source of truth for the repository layer
web/                   # SolidJS frontend
api/v1alpha1/          # K8s CRD types — generated deepcopy
config/operator/       # CRD manifests + RBAC (controller-gen output; do not edit)
.tektonic/             # CI source of truth → generates .tekton/
tests/                 # Integration tests (testcontainers)
```

## Code Conventions

- Standard Go layout; explicit error handling, propagate up and handle at boundaries
- `context.Context` for cancellation and deadlines
- Table-driven tests; document all exported functions and types
- Cyclomatic complexity limit: 15 (`.golangci.yml`)
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- TDD: failing test first. For diff/tree code see
  [docs/DEVELOPMENT.md § Testing diff/tree changes](docs/DEVELOPMENT.md#testing-difftree-changes)
- Prefer small, composable, idiomatic libraries over batteries-included frameworks

## Issue Tracking & Branching

`bd prime` runs at session start and covers the command reference. What follows is
ocidex-specific and overrides the beads defaults.

**One branch per epic.** Every story belongs to an epic; branch from `main` once at the start and
work all child stories there. In a new session, `git checkout <epic-id>` before touching code —
never work directly on `main`.

```bash
bd ready                                        # unblocked work
bd show <id>                                    # note the parent epic ID
git checkout <epic-id> || git checkout -b <epic-id>   # epic branch, from an up-to-date main

bd update <id> --status=in_progress             # claim before coding
# ... implement ...
git add <changed files> .beads/issues.jsonl     # stage code AND beads state together
git commit -m "feat: description (<issue-id>)"  # commit BEFORE closing
bd update <id> --notes "Files: ...\nApproach: ..."
bd close <id>

# epic complete — human reviews `git log main..<epic-id>` first
git checkout main && git pull --rebase
git merge <epic-id> --no-ff -m "feat: complete <epic-title> (<epic-id>)"
git push
bd close <epic-id> && git branch -d <epic-id>
```

**Pushing the epic branch is free — do it.** The push pipeline's trigger is
`{ on: PUSH, branch: "main" }` (`.tektonic/pipeline.ts`), so a feature-branch push runs no CI at
all. It is the cheapest way to keep work off a single machine, and there is no reason to leave a
session's work unpushed. **Merging to `main` is the CI-triggering event** (~70 min warm, 3 h
timeout), so merge once per epic, not once per story.

**Other conventions:**

- Create the issue *before* writing code.
- Priority is `0`–`4` (`0` = critical). Not `high`/`medium`/`low`.
- Hierarchical IDs (`<epic>.<n>`) come from `--parent` at create time; cross-issue links from
  `bd dep add <issue> <depends-on>`.
- Never close without recording how it was resolved — `bd update <id> --notes` or
  `bd close <id> --reason "..."` for trivial changes.
- `bd dolt push` at session end is always safe.

**Chained epics.** Epics are never nested — an epic that depends on another is a **sibling**
linked with `bd dep add <epic> <depends-on>`. Nesting breaks the branch model (a parent's branch
would hold every child epic's work) and `/work-epic`, whose loop implements one story per
iteration. If a "sub-epic" doesn't deserve its own branch and its own `/work-epic` run, it's a
story; to group epics without ordering them, use a label, not a parent.

Merge to `main` in dependency order, one epic at a time — **do not stack branches**. The next
epic branches from the *new* `main`, so it starts with its dependency's work in place and never
rebases. Siblings blocked only on a common parent branch from `main` in parallel once that parent
merges; each rebases on `main` before its own merge. Stacking
(`git checkout -b <next> <prev>`) is the exception, justified only when the previous epic's
review is blocked and the work cannot wait — any review change to the parent then forces a rebase
of every dependent commit.

## Architecture Decisions

Every major technical choice has an ADR in [docs/adr/](docs/adr/) — read the relevant one before
changing the area it governs, and write a new one for a decision of comparable weight.

- **Diff, dependency-tree, or changelog code → read ADRs 0019–0021 first.** They are the
  normative contract; the implementation issues (`ocidex-bqh.*`) reference them by section.
- **New API handler →** huma v2 pattern: `huma.Register(api, huma.Operation{...}, handler)` with
  typed input/output structs. See `internal/api/sbom.go` and
  [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
- **New enricher →** implement `enrichment.Enricher`, add `cmd/<name>-worker/` and a Dockerfile
  stage, and register it in `internal/enrichment/deps.go` (`rootEnrichers`, or an edge in
  `enricherDeps` if it needs another enricher's output). See ADRs 0026, 0033, 0035 and
  [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) "Adding a New Enricher".

## Where Things Are Documented

| Topic | Document |
|---|---|
| System design, data model, layering | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Coding patterns, testing, adding an enricher | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| Environment variables | [docs/CONFIGURATION.md](docs/CONFIGURATION.md) |
| Tekton CI: fast iteration, gotchas, script syntax | [docs/CI_TEKTON.md](docs/CI_TEKTON.md) |
| Frontend dev rigs, browser verification | [docs/FRONTEND_DEV.md](docs/FRONTEND_DEV.md) |
| Local Talos + Tilt cluster loop | [docs/K8S_DEV.md](docs/K8S_DEV.md) |
| Production deployment (K8s + Flux) | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Operations and runbooks | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| SBOM ingestion paths | [docs/INGESTION.md](docs/INGESTION.md) |
| Auth/authz matrix | [docs/AUTH_MATRIX.md](docs/AUTH_MATRIX.md) |
| Diff views, identity rules, flavor axis | [docs/SBOM_DIFF.md](docs/SBOM_DIFF.md) |
| Cluster page tabs, coverage semantics | [docs/CLUSTER_INVENTORY.md](docs/CLUSTER_INVENTORY.md) |
| MCP server setup and tools | [docs/MCP.md](docs/MCP.md) |
| Ephemeral `--once` job mode | [docs/EPHEMERAL_JOBS.md](docs/EPHEMERAL_JOBS.md) |
| API versioning policy | [docs/API_VERSIONING.md](docs/API_VERSIONING.md) |
| Image labeling | [docs/IMAGE_LABELING.md](docs/IMAGE_LABELING.md) |
| Verifying released artifacts | [docs/verifying-artifacts.md](docs/verifying-artifacts.md) |
| Cross-repo work (apko-cicd, tektonic) | [AGENTS.md](AGENTS.md), `~/code/CLAUDE.md` |

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
<!-- END BEADS INTEGRATION -->

## Session Completion

Overrides the beads session-close protocol. At the end of a work session:

1. File issues for anything needing follow-up.
2. Run the quality gates if code changed — tests, linters, build.
3. Close finished work; update in-progress items with notes.
4. **Commit everything**, including `.beads/issues.jsonl`. Uncommitted work is at risk.
5. **Push the epic branch** — it triggers no CI (see "Issue Tracking & Branching"), and
   `bd dolt push` is always safe.
6. Merge to `main` only when the whole epic is done — that is the one CI-triggering push.
7. Hand off with context for the next session.
