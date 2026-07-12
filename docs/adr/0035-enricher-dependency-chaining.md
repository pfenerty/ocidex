---
status: "accepted"
date: 2026-07-12
decision-makers: Patrick Fenerty
---

# Enricher Dependency Chaining

## Context and Problem Statement

`ocidex-2jb.1` added a declared enricher dependency graph
(`internal/enrichment/deps.go`): `enricherDeps` maps an enricher name to the
prerequisite enrichers that must succeed before it can run (currently
`"git": {"oci-metadata"}`), with `Dependents`/`Prerequisites` accessors. That
graph was purely declarative — nothing read it. A completed `oci-metadata` job
never caused `git` to be enqueued, so the upcoming Git enricher
(`ocidex-2jb.5`) would need a caller to enqueue it manually, defeating the
point of declaring the dependency at all.

The question is where the runtime enqueue-on-completion behavior belongs, and
whether it needs new infrastructure beyond the existing outbox/doorbell.

## Decision Drivers

- Reuse the existing `enrichment_jobs` outbox + `.enrich.hint` NATS doorbell
  (ADR-0024) rather than introduce a second queueing mechanism for chained
  work.
- The `--once` K8s Job mode (ADR-0027) processes exactly one SBOM and exits;
  it must not become an implicit chaining trigger, since that would make
  ephemeral Job runs have side effects beyond their single enrichment.
- Keep the chaining logic generic (graph-driven), not per-enricher
  special-casing, so adding a third dependent enricher later requires no new
  code — only a `deps.go` entry.

## Considered Options

1. **Enqueue dependents from a central scheduler/cron job** that periodically
   scans `enrichment` rows for newly-succeeded prerequisites.
2. **Completion-driven enqueue in the daemon worker loop** (chosen) — after a
   job finishes successfully, check the graph and enqueue any now-ready
   dependents inline.
3. **Push chaining into each `Enricher` implementation** (e.g. `oci-metadata`
   directly enqueues `git` on success).

## Decision Outcome

Chosen: **option 2**, implemented in `internal/worker/enrichment/deps.go`
(`enqueueDependents`), called from `internal/worker/enrichment/worker.go`'s
`enrichProcessor` immediately after a successful `FinishByID`.

A central scanner (option 1) adds a second polling loop and a delay window
that the existing hint-driven design was built to avoid. Per-enricher
chaining (option 3) would couple every enricher implementation to the
dependency graph and duplicate the ready-check across each one; the graph is
already centralized in `deps.go`, so the enqueue logic belongs next to it,
not fanned out across enrichers.

### Completion-driven enqueue

On successful completion of an enrichment job, the worker calls
`enrichment.Dependents(completedEnricher)` to find enrichers that declare the
just-completed one as a prerequisite. For each dependent, every entry in
`enrichment.Prerequisites(dependent)` is checked via `GetEnrichment`; the
dependent is enqueued only if all prerequisites have `status = "success"`.
Any `GetEnrichment` error (including "no row yet") is treated the same as a
non-`success` status — not ready, skip. `Enqueue` is idempotent (unique
violation on the `sbomID:enricherName` key is swallowed), so this is safe to
call redundantly if multiple prerequisites of the same dependent complete
around the same time.

### No new tables or subjects

Dependent jobs are inserted into the same `enrichment_jobs` table via the
same `EnrichJobService.Enqueue` used for root enrichers, and the same
`.enrich.hint` NATS subject is published as a best-effort wake-up — mirroring
`internal/enrichment/submitter.go`'s existing enqueue+publish pattern. The
poll loop remains the source-of-truth fallback if the hint publish fails.

### `--once` mode does not chain

`RunOnce` (the K8s Job entry point) never calls `EnrichJobService` or
`FinishByID` — it runs the dispatcher directly against a single SBOM and
exits. It therefore cannot reach the chaining hook at all; this is a
structural property of the code path, not an added guard.

## Consequences

- Good: adding a new dependent enricher requires only a `deps.go` graph entry
  — no changes to the worker loop or scheduler.
- Good: no new queue, table, or NATS subject; chaining rides the existing
  outbox/doorbell.
- Good: idempotent `Enqueue` makes the fan-in-safe by construction — no
  dedup logic needed in `enqueueDependents` itself.
- Bad — chaining only happens on the daemon path. If a dependent's
  prerequisite job runs via `--once` (e.g. a one-off backfill Job), the
  dependent will not be enqueued automatically; it must be enqueued
  separately. This is accepted since `--once` is intended for isolated,
  single-enrichment runs, not for driving the full pipeline.

## More Information

- [ADR-0024: Outbox Pattern for Scan Queue](0024-outbox-pattern-for-scan-queue.md) —
  the `enrichment_jobs` outbox + NATS doorbell pattern this reuses.
- [ADR-0026: Pluggable Enricher Interface](0026-pluggable-enricher.md) —
  the `Enricher`/`Dispatcher` model the dependency graph sits alongside.
- [ADR-0027: Ephemeral Job Contract](0027-ephemeral-job-contract.md) — defines
  the `--once` mode that structurally cannot chain.
- Epic `ocidex-2jb` (Git enricher). `ocidex-2jb.1` added the declared graph;
  this ADR covers `ocidex-2jb.2`'s runtime enqueue; `ocidex-2jb.5` (the Git
  enricher itself) depends on this behavior to be enqueued automatically.

## Key Files

- `internal/enrichment/deps.go` — declared dependency graph (`Dependents`,
  `Prerequisites`)
- `internal/worker/enrichment/deps.go` — `enqueueDependents`, readiness check,
  hint publish
- `internal/worker/enrichment/worker.go` — `enrichProcessor` calls
  `enqueueDependents` after a successful `FinishByID`
- `internal/enrichment/submitter.go` — the enqueue+publish pattern this
  reuses for root enrichers
