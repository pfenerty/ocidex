---
status: "accepted"
date: 2026-05-30
decision-makers: Patrick Fenerty
---

# Postgres-as-queue (transactional outbox) for the scanner pipeline

## Context and Problem Statement

The scanner pipeline historically tracked queued work in two places:

1. The `scan_jobs` table — `state` ∈ {queued, running, succeeded, failed}.
2. A NATS JetStream subject (`ocidex.scan.requested`) carrying the full
   `ScanRequest` payload, with `Nats-Msg-Id = registry_id@digest` for
   producer-side dedup.

Producers wrote the DB row, then published. Consumers (scanner-workers)
pulled the NATS message, transitioned the DB row, ran Syft, and acked.
NATS handled retry via `AckWait` + `MaxDeliver`; a JetStream subject
(`ocidex.scan.dlq`) and a `scan_job_failures` audit table caught the
exhausted messages.

This is the classic **dual-write** antipattern: two systems that are
supposed to agree about the same fact ("this work needs to happen"),
with no atomic write spanning both. Every consistency gap had to be
papered over:

| Gap | Band-aid |
|---|---|
| Producer writes row, NATS publish fails | Orphan reconciler (5b1493e): republishes any row queued > 10m |
| Same Nats-Msg-Id republished after JetStream's 5-min dedup window | Exponential backoff + max-attempts cap (ocidex-ujj.73.4) |
| Reconciler floods stream with duplicates of slow-but-not-orphaned rows | Per-tick batch cap (100) — but still causes duplicate scans |
| Per-pod fairness with shared MaxAckPending | Decouple MaxAckPending from per-pod concurrency (ocidex-ujj.73.3) |
| DLQ messages need visibility | scan_job_failures table + admin /dlq endpoint |

The recent prod incident (1093 queued, 574 failed, 0 running, workers
busily re-scanning already-succeeded images) was the cumulative cost of
this design: the reconciler's "queued > 10m means orphaned" premise is
false on a throughput-bound (Pi4, ~24 scans/hour) cluster, so legitimate
queue depth triggers duplicate publishes.

## Decision Drivers

* The single-pod NATS deployment is an intentional SPOF for current
  hardware (multi-replica JetStream needs quorum). Anything that makes the
  queue's availability == NATS's availability is a liability.
* Postgres is already a hard dependency and the system of record for
  every other entity. Adding queue state to it adds zero new infra.
* We already have rich operator tooling against the `scan_jobs` table
  (admin UI, status endpoint, worker_id tracking). Pattern A would require
  rebuilding that against NATS consumer info.
* The dual-write antipattern's failure modes have all proved to be
  load-bearing in practice; this is not theoretical risk.

## Considered Options

* **A. NATS as source of truth (queue-driven).** The stream is the queue;
  DB holds results only. Visibility via `nats consumer info`.
* **B. Postgres as source of truth (outbox pattern).** The `scan_jobs`
  row's existence IS the enqueue. NATS carries only `{id}` hints for
  fast wakeup. Workers also poll the DB as a fallback.
* **C. Drop the DB queue, use NATS-only with a results table** (variant
  of A).

## Decision Outcome

Chosen: **B — Postgres as source of truth (transactional outbox).**

The DB row is the single statement of "this work needs to happen." NATS
messages are pure transport for fast wakeup. Workers wake on NATS hint
OR a 30s DB poll; either path leads to `ClaimByID`/`ClaimNext`, which
`UPDATE … WHERE state='queued' RETURNING` with `FOR UPDATE SKIP LOCKED`.
The row-level claim is the only coordination — no `MaxAckPending`, no
`Nats-Msg-Id` dedup, no reconciler.

Retry policy is in one place: `FailOrRequeueByID` increments `attempts`
and either resets to `queued` (when `attempts < max`) or marks `failed`
(when `attempts >= max`). The only stuck-job sweep is
`RequeueStuckRunning`, which moves rows whose worker hasn't updated
`last_attempt_at` within 15 min back to `queued`.

### Consequences

* Good: no reconciler. NATS failure modes (pod restart, PVC loss,
  publish failures) all resolve to "the poll loop drains the queue."
* Good: counts in the admin UI are trivially correct — there's only one
  source of truth.
* Good: idempotency comes for free at the row level via the existing
  `nats_msg_id` UNIQUE constraint (kept as an idempotency key under its
  legacy name).
* Good: net deletion. The atomic switch removed ~700 lines of code that
  existed only to coordinate the dual write.
* Bad: workers poll the DB every 30s even when nothing is queued. On
  Pi4 throughput this is irrelevant; on a much larger deployment it
  would warrant tuning.
* Bad: small write amplification from the claim's `UPDATE` per
  processed row. Trivial at current scale.

### Confirmation

* `tests/scan_to_enrich_test.go` exercises the full producer →
  hint-extension → worker → ingest flow against real NATS + Postgres
  containers.
* Production observability: the absence of "skipping duplicate sbom
  ingestion" log lines from the scanner-workers under steady-state
  load confirms duplicate work is no longer being generated.

## Pros and Cons of the Options

### A — NATS as source of truth

* Good, because the queue is the queue. Idiomatic for systems built
  NATS-first.
* Good, because no DB write per claim.
* Bad, because queue availability == NATS availability, and our NATS
  is a single-pod SPOF.
* Bad, because operator visibility ("what's queued?") moves from
  Postgres to JetStream consumer info, breaking existing tooling.
* Bad, because if the stream is wiped, we need a re-discovery
  mechanism (re-walk the catalog, re-emit webhooks) — outboard from
  the queue itself.

### B — Postgres as source of truth

* Good, because we already have a heavily-used DB state machine; this
  formalizes what's de facto true.
* Good, because no dual-write. Every consistency gap collapses to
  "ask the DB."
* Good, because NATS failure modes degrade to higher queue latency
  instead of dropped work.
* Bad, because polling has a base cost (one query per worker per poll
  interval).
* Bad, because the queue's throughput is bounded by Postgres
  write/UPDATE rate. Irrelevant for our deployment.

### C — NATS only (no DB queue)

* Good, because simplest model.
* Bad, because we'd lose the existing admin tooling and have to rebuild
  it against NATS consumer info, for no benefit.

## More Information

Implementation tracked under `ocidex-ujj.74` (epic) with sub-issues for
each phase. Superseded the design that produced ADR 5b1493e
(orphan reconciler), 12e6049 (MaxAckPending decoupling), and the entire
`scan_job_failures` DLQ-via-NATS plumbing.

References: [Transactional Outbox pattern](https://microservices.io/patterns/data/transactional-outbox.html)
— the same pattern with a different name, applied to a single-app
deployment.
