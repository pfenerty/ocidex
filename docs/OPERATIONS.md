# OCIDex Operations Playbook

Runbook for production incidents involving the scanner pipeline. Pair with `docs/INGESTION.md` (Path E) for architectural detail and `docs/adr/0024-outbox-pattern-for-scan-queue.md` for the design rationale.

## Topology recap

- **Postgres** — system of record for everything, including queued work (`scan_jobs.state='queued'`). The transactional outbox: a producer's DB insert IS the enqueue.
- **NATS** — single-pod standalone JetStream, PVC-backed. Carries only `{id}` hints on `ocidex.scan.hint` to wake workers faster than the 30s poll cadence. No retry, no dedup window dependency, no DLQ subject. Failure of NATS reduces the pipeline to "drains at poll cadence" — never "drops work."
- **API server** — producer. The webhook handler and the catalog walker both insert `scan_jobs` rows + publish hints via `NATSSubmitter.Submit`.
- **scanner-worker** — N replicas. Each runs `SCANNER_MAX_CONCURRENCY` goroutines that wake on NATS hints OR the 30s DB poll, claim a row via `UPDATE…RETURNING`, run Syft, and finish/fail the row. Plus one stuck-running sweep goroutine.
- **enrichment-worker** — N replicas. Same NATS as before (one-shot SBOMIngested events; no queue depth, no reconciler ever existed here).

## Health surfaces

| Endpoint | Process | What it checks |
|---|---|---|
| `GET /health` (8080) | API | Always 200 if process is up. |
| `GET /ready` (8080) | API | DB ping. |
| `GET /healthz` (9090) | scanner-worker, enrichment-worker | Process up. |
| `GET /readyz` (9090) | scanner-worker, enrichment-worker | NATS Connected + DB Ping <1s. |
| `GET /api/v1/admin/status` | API (admin-only) | Counts from `scan_jobs` by state, DB latency. The counts are trivially correct — there is no second source. |
| `POST /api/v1/admin/jobs/{id}/retry` | API (admin-only) | Resets a `failed` row to `queued`. |

Worker pods log NATS disconnect / reconnect / closed at WARN — grep for these to see connection flaps.

## Common incidents

### 1. Queue is not draining

**Symptoms.** `queued` count is increasing or static. No worker progress in the admin Jobs tab.

**Diagnosis.**

- Check scanner-worker readiness: `kubectl get pods -l app=ocidex-scanner-worker`. `0/1 Ready` means the readiness probe is failing — NATS conn dropped *and* DB ping >1s.
- Tail the worker log. The poll loop is silent when there is nothing queued, but `ClaimNext` errors will appear if the DB is unreachable.
- Check resource limits: Syft typically uses 200–600 MB; if pods are OOMKilled the scanner stops claiming.

**Recovery.**

- Transient NATS drop: workers auto-reconnect (`MaxReconnects=-1`, `ReconnectWait=2s`). No action — they keep polling and processing meanwhile.
- DB outage: blocks everything. Fix Postgres.
- Worker OOM: raise the K8s memory limit or lower `SCANNER_MAX_CONCURRENCY`.

### 2. NATS pod won't start

**Symptoms.** `kubectl get pods -l app=nats` shows `CrashLoopBackOff`. **Under the outbox model this is not a production-stopping incident** — workers fall back to 30s DB polling and the queue keeps draining.

**Diagnosis.** PVC unavailable, disk full, or corrupted JetStream metadata. `kubectl describe pvc nats-data-nats-0` and the NATS pod logs are the first stops.

**Recovery.** Whichever the root cause, fix NATS at your own pace. Until then expect a worst-case ~30s extra queue latency per row. No data loss is possible: the producer's row commit happened in Postgres; the NATS hint is a luxury.

### 3. Stuck-running rows

**Symptoms.** A `running` row's `last_attempt_at` is older than `SCANNER_STUCK_THRESHOLD` (default 15 min). Usually means the worker pod was evicted, terminated mid-scan, or networked into a hung Syft.

**Recovery.** Automatic — `runStuckRunningSweep` runs every `SCANNER_STUCK_THRESHOLD/3` (default every 5 min) and moves the row back to `queued` (or to `failed` if `attempts >= SCANNER_MAX_ATTEMPTS`). Operator action only needed if the same row repeatedly cycles through the sweep — that points at a genuine Syft / registry problem on that specific image.

### 4. Failed rows accumulating

**Symptoms.** `state='failed'` count growing. Visible in the admin Jobs tab with the state filter set to `failed`. Each row's `last_error` carries the verbatim error.

**Diagnosis by `last_error`:**

- `manifest unknown` / `404 NotFound` — image was deleted between scheduling and scanning. Nothing to do.
- `connect: connection refused` — registry was unreachable. Either retry once it's back (Retry button on the row) or accept it.
- `syft: …` — actual analysis failure. File a `bd` issue with the row id and digest.
- `stuck: worker did not complete and retries exhausted` — the row cycled through the stuck-running sweep `SCANNER_MAX_ATTEMPTS` times. Usually a specific image Syft can't handle.

**Recovery.** Click Retry on the row to reset it to `queued`. The next poll or hint picks it up with `attempts=0`. For bulk retry: `UPDATE scan_jobs SET state='queued', attempts=0, last_error=NULL WHERE state='failed' AND last_error LIKE '%pattern%'`.

### 5. Manual re-enqueue of a specific image

```bash
curl -X POST "$OCIDEX_API/api/v1/registries/$REGISTRY_ID/scan" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"repository":"library/alpine","digest":"sha256:…","tag":"latest"}'
```

The submitter inserts the row + publishes a hint. If a row with the same `(registry, digest)` is already queued/running, the producer returns no error and no duplicate is created (UNIQUE constraint at the row level).

### 6. Duplicate scans / wasted worker cycles

**Should not happen under the outbox model.** If you see `skipping duplicate sbom ingestion` log lines from the scanner-worker, something has regressed — file an issue. Under the old (NATS-as-queue) design this was caused by the orphan reconciler republishing slow-but-not-orphaned rows; the redesign removed that path entirely.

## Routine maintenance

- **PVC backups** — back up the Postgres volume. The NATS volume is now no-data: at worst, losing it costs you queue latency until workers' next poll, which is bounded by `SCANNER_POLL_INTERVAL`.
- **Tuning concurrency** — `SCANNER_MAX_CONCURRENCY` directly maps to active worker goroutines. Watch pod memory: Syft is the cost. There is no longer a `SCANNER_MAX_ACK_PENDING` to tune in lockstep.
- **DLQ table cleanup** — `scan_job_failures` is the legacy DLQ-via-NATS audit table. It is no longer written to. `SCAN_DLQ_RETENTION_DAYS` (default 30) controls how long old rows linger before the purge sweep deletes them. The table itself is scheduled for removal in a follow-up migration (`ocidex-ujj.74.6`).
