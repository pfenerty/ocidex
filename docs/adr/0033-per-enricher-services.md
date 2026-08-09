# ADR 0033: Per-Enricher Services

**Status:** Accepted  
**Date:** 2026-06-27

## Context

The monolithic `enrichment-worker` binary registered all three enrichers (`oci-metadata`, `user`, `provenance`) and consumed a single `enrichment_jobs` queue partition (`enricher_name='all'`). The provenance enricher makes OCI registry API calls and runs ECDSA verification — significantly slower and more failure-prone than the `oci-metadata` or `user` enrichers. Running them in the same process couples their scaling and failure domains, and prevents independent retry tuning or rollout.

## Decision

### Database: `enrichment_jobs.enricher_name` partition

Migration `db/migrations/00036_per_enricher_jobs.sql` adds:

```sql
ALTER TABLE enrichment_jobs ADD COLUMN enricher_name TEXT NOT NULL DEFAULT 'all';
ALTER TABLE enrichment_jobs ADD CONSTRAINT enrichment_jobs_sbom_enricher_unique
    UNIQUE (sbom_id, enricher_name);
CREATE INDEX idx_enrichment_jobs_enricher_queued
    ON enrichment_jobs (enricher_name, created_at) WHERE state = 'queued';
```

`ClaimNext` in `internal/service/enrichjob.go` filters `WHERE enricher_name = ?`, so each worker claims only its own rows.

### Fan-out on ingest

When a new SBOM is ingested, `internal/service/enrichjob.go:CreateForSBOM` inserts one `enrichment_jobs` row per entry in `knownEnrichers` (`"oci-metadata"`, `"user"`, `"provenance"`). The legacy `"all"` row is also inserted during the transition period to keep the monolithic worker functional.

### Per-enricher binaries and NATS consumers

Each enricher gets its own `cmd/<name>-worker/main.go` (~30 lines) that calls the shared scaffolding:

```go
enrichmentworker.Run(buildEnrichers, enrichmentworker.RunConfig{
    EnricherName: "<name>",
    HintDurable:  "enrich-hint-<name>",
})
```

The `HintDurable` value is a unique JetStream durable consumer name per worker type. All workers subscribe to the shared hint subject (`.enrich.hint`); durable consumers ensure each worker type sees every hint exactly once without competing with other worker types.

| Binary | `EnricherName` | `HintDurable` |
|--------|---------------|---------------|
| `cmd/oci-metadata-worker` | `oci-metadata` | `enrich-hint-oci-metadata` |
| `cmd/user-enricher-worker` | `user` | `enrich-hint-user` |
| `cmd/provenance-worker` | `provenance` | `enrich-hint-provenance` |

### Shared scaffolding

`internal/worker/enrichment/worker.go` exposes:

```go
type RunConfig struct {
    EnricherName string
    HintDurable  string
}

type EnricherFactory func(pool *pgxpool.Pool) []enrichment.Enricher

func Run(factory EnricherFactory, cfg RunConfig) error   // daemon mode
func RunOnce(ctx context.Context, pool *pgxpool.Pool, factory EnricherFactory) error  // --once K8s Job mode
```

The factory receives the live DB pool so resolver-dependent enrichers (`oci-metadata`, `provenance`) can be built after the pool is created inside `Run`.

### Docker images and CI

Each binary has a dedicated stage in `docker/Dockerfile` (`FROM gcr.io/distroless/static-debian12:nonroot AS <name>`). Three `imageSpecs` entries in `.tektonic/jobs/image-build/spec.ts` generate six Tekton tasks (build + release per enricher), serial-chained after the existing `enrichment-worker` tasks.

### Adding a new enricher

1. Implement `enrichment.Enricher` in `internal/enrichment/<name>/`.
2. Add `names.<Name>` to `rootEnrichers` in `internal/enrichment/deps.go` — or, if it consumes another enricher's output, add an edge to `enricherDeps` there instead (ADR-035).
3. Create `cmd/<name>-worker/main.go` (~30 lines, calls `enrichmentworker.Run`).
4. Add a `FROM … AS <name>-worker` stage in `docker/Dockerfile` and a build line in the builder stage.
5. Add `["<name>-worker", "docker/Dockerfile", "<name>-worker"]` to `imageSpecs` in `.tektonic/jobs/image-build/spec.ts` and run `make tekton-synth`.

## Consequences

- The legacy `enrichment-worker` (claiming `enricher_name='all'`) must be kept operational until the per-enricher workers are validated in production. Remove the `'all'` fan-out row and the legacy binary once stable. **Done — see the update below.**
- The NATS hint subject is shared; per-enricher isolation is achieved through durable consumer names, not separate subjects.
- CPU-intensive enrichers (provenance) can be scaled independently via separate K8s Deployments with their own resource limits.

## Update (2026-08-09, ocidex-kg5)

The transition is over. `ocidex-07x` validated the per-enricher workers end to end, and the
monolith has been removed: `cmd/enrichment-worker/`, its `docker/Dockerfile` stage, its two
generated Tekton tasks, and its `imageSpecs` / `shippedBinaries` / `COMPONENTS` entries are all
gone. `db/migrations/00057_remove_all_enricher_jobs.sql` deletes every `enricher_name='all'` row
and drops the column DEFAULT that 00036 added, so a caller that omits `enricher_name` now hits a
NOT NULL violation instead of silently landing in a partition no worker claims.

The submitter had already stopped writing `'all'` rows when it switched to `rootEnrichers`.
`NewEnrichJobService`'s enricher name scopes `ClaimNext` only; the API and `scanner-worker`
enqueue but never claim, so they pass `""`.

## Key Files

- `db/migrations/00036_per_enricher_jobs.sql` — schema changes
- `db/migrations/00057_remove_all_enricher_jobs.sql` — removal of the `'all'` partition
- `internal/service/enrichjob.go` — `NewEnrichJobService`, `Enqueue`, `ClaimNext`
- `internal/enrichment/deps.go` — `rootEnrichers`, `enricherDeps` (was `knownEnrichers`)
- `internal/worker/enrichment/worker.go` — `Run`, `RunOnce`, `RunConfig`, `EnricherFactory`
- `cmd/oci-metadata-worker/main.go`, `cmd/user-enricher-worker/main.go`, `cmd/provenance-worker/main.go`
- `docker/Dockerfile` — per-enricher runtime stages
- `.tektonic/jobs/image-build/spec.ts` — `imageSpecs` entries
- `docs/adr/0024-outbox-pattern-for-scan-queue.md` — queue mechanics
- `docs/adr/0026-pluggable-enricher.md` — Enricher interface
