# OCIDex Operations Playbook

Runbook for production incidents involving the NATS JetStream + scanner-worker pipeline. Pair with `docs/INGESTION.md` for the architectural detail.

## Topology recap

- **NATS** — single standalone pod (`k8s/base/nats-statefulset.yaml`), `-js --store_dir /data`, PVC-backed. Stream `ocidex`, subjects `ocidex.>`, `FileStorage`, `MaxAge=24h`, `Duplicates=5m`. **No clustering** — quorum needs ≥3 nodes which the prod hardware does not have.
- **Producers** — API server (webhook + admin manual-scan) and scanner-worker (catalog walks) publish to `ocidex.scan.requested`.
- **Consumers** — durable `scanner` consumer on `ocidex.scan.requested` (AckWait 10 min, MaxDeliver 3), durable `enrichment` consumer on `ocidex.sbom.ingested` (AckWait 5 min, MaxDeliver 5).
- **State** — every scan has a `scan_jobs` row inserted before publish; reconciler repairs any DB-row-without-message.

## Health surfaces

| Endpoint | Process | What it checks |
|---|---|---|
| `GET /health` (8080) | API | Always 200 if process is up. |
| `GET /ready` (8080) | API | DB ping. |
| `GET /healthz` (9090) | scanner-worker, enrichment-worker | Process up. |
| `GET /readyz` (9090) | scanner-worker, enrichment-worker | NATS conn `Connected` + DB ping <1s. |
| `GET /api/v1/admin/status` | API (admin-only) | NATS enabled, scanner/enrichment enabled, queued/running counts, 24h success/fail counts, DB latency. |
| `GET /api/v1/admin/dlq` | API (admin-only) | Paginated dead-letter rows. |
| Admin → Jobs → Dead Letter | Web UI | Same data as `/admin/dlq`, with auto-refresh. |

Worker pods log NATS disconnect / reconnect / closed events at WARN — grep for `nats disconnected` or `nats reconnected` to see connection flaps.

## Common incidents

### 1. Scan jobs are stuck in `queued`

**Symptoms.** Admin status shows non-zero `queued` count that is not draining. Jobs UI shows rows older than 10 min still queued.

**Diagnosis.**

- Check the scanner-worker readiness probe: `kubectl get pods -l app=ocidex-scanner-worker`. A pod in `0/1 Ready` means it can't reach NATS or the DB.
- Tail the worker log for `reconciler: tick complete claimed=N republished=M`. If `claimed > 0`, the reconciler is doing its job; jobs should drain within the next AckWait cycle.
- If `claimed = 0` but jobs are still queued, the *registry itself* may be unreachable — check the `last_error` once the job transitions to `failed` after 6 reconcile attempts (~7h).

**Recovery.**

- Transient NATS conn drop: the worker auto-reconnects (`MaxReconnects=-1`, `ReconnectWait=2s`). No action.
- NATS pod evicted / PVC reattached: orphan reconciler republishes within 10 min of the new stream existing. No action.
- Stream genuinely gone (PVC lost, dev wipe): same path — reconciler republishes the queued jobs on its next tick (≤5 min).

### 2. NATS pod won't start

**Symptoms.** `kubectl get pods -l app=nats` shows `CrashLoopBackOff`. All scan ingestion halts.

**Likely causes.**

- PVC unavailable (storage class issue) — `kubectl describe pvc nats-data-nats-0`.
- Disk full on the node — `kubectl describe pod` will say `FailedScheduling` or the container will exit with disk errors. Free space or evacuate.
- Corrupted JetStream metadata after an ungraceful shutdown — extremely rare; check the NATS pod logs for `unable to recover stream`. Recovery: scale to 0, take a PVC backup, then either restore from backup or delete the PVC contents (this loses in-flight messages; the orphan reconciler will republish DB-tracked jobs).

### 3. Dead-letter pile-up

**Symptoms.** Admin → Jobs → Dead Letter shows a growing count. Same `failure_reason` repeats.

**Diagnosis.** The `failure_reason` column is the Syft / ingest error verbatim. Common patterns:

- `manifest unknown` / `404 NotFound` — image was deleted from the registry after the scan was scheduled. Nothing to do.
- `connect: connection refused` — registry is down. Fix upstream.
- `syft: …` — actual analysis failure. File a `bd` issue; attach the failure row.

**Recovery.** DLQ rows older than `SCAN_DLQ_RETENTION_DAYS` (default 30) are purged automatically by the scanner-worker every hour. Set `SCAN_DLQ_RETENTION_DAYS=0` to disable purging.

### 4. Manual re-enqueue of a specific image

Trigger a webhook-style scan against the existing API endpoint. The producer side handles idempotency via `nats_msg_id = registry_id@digest`:

```bash
curl -X POST "$OCIDEX_API/api/v1/registries/$REGISTRY_ID/scan" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"repository":"library/alpine","digest":"sha256:…","tag":"latest"}'
```

If the digest has been scanned in the last 5 min the JetStream dedup window drops the duplicate. To force a re-scan despite that, wait 5 min or run a fresh tag/digest.

### 5. Reconciler is republishing the same job every 5 min

This is by design for the first few attempts (10 min, 20 min, 40 min, 80 min, 80 min, 80 min). After 6 attempts the row is failed with `last_error = 'orphaned: max reconcile attempts'` and the reconciler stops.

If a job is going through every backoff window and never running, something is wrong with the consumer side: check the scanner-worker pod's readiness probe and logs.

## Routine maintenance

- **PVC backups** — back up `pvc/nats-data-nats-0` and the Postgres volume on the same cadence. The DB-only restore + orphan reconciler can recover from a NATS loss; the reverse (NATS-only + lost DB) cannot.
- **Bumping concurrency** — start with `SCANNER_MAX_CONCURRENCY` and watch memory: Syft routinely uses 200–600 MB per scan depending on image size. If you raise per-pod concurrency past `4`, also raise `SCANNER_MAX_ACK_PENDING` to `concurrency × replicas + slack`.
- **DLQ inspection cadence** — quarterly is fine in steady state. The Dead Letter view's count badge surfaces the absolute number on every visit to the Jobs tab.
