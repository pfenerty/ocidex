# OCIDex Operations Playbook

Runbook for production incidents involving the scanner pipeline. Pair with `docs/INGESTION.md` (Path E) for architectural detail and `docs/adr/0024-outbox-pattern-for-scan-queue.md` for the design rationale.

## Topology recap

- **Postgres** — system of record for everything, including queued work (`scan_jobs.state='queued'`). The transactional outbox: a producer's DB insert IS the enqueue.
- **NATS** — single-pod standalone JetStream, PVC-backed. Carries only `{id}` hints on `ocidex.scan.hint` to wake workers faster than the 30s poll cadence. No retry, no dedup window dependency, no DLQ subject. Failure of NATS reduces the pipeline to "drains at poll cadence" — never "drops work."
- **API server** — producer. The webhook handler and the catalog walker both insert `scan_jobs` rows + publish hints via `NATSSubmitter.Submit`.
- **scanner-worker** — N replicas. Each runs `SCANNER_MAX_CONCURRENCY` goroutines that wake on NATS hints OR the 30s DB poll, claim a row via `UPDATE…RETURNING`, run Syft, and finish/fail the row. Plus one stuck-running sweep goroutine.
- **per-enricher workers** (`oci-metadata-worker`, `git-worker`, `user-enricher-worker`, `provenance-worker`) — one Deployment each, N replicas, each claiming its own `enrichment_jobs.enricher_name` partition (ADR-033). Same NATS as before (one-shot SBOMIngested events; no queue depth, no reconciler ever existed here).

## Health surfaces

| Endpoint | Process | What it checks |
|---|---|---|
| `GET /health` (8080) | API | Always 200 if process is up. |
| `GET /ready` (8080) | API | DB ping. |
| `GET /healthz` (9090) | scanner-worker, enricher workers | Process up. |
| `GET /readyz` (9090) | scanner-worker, enricher workers | NATS Connected + DB Ping <1s. |
| `GET /metrics` (9090) | API, every worker, k8s-agent | Prometheus metrics; see [Metrics](#metrics). Never routed through the ingress. |
| `GET /api/v1/admin/status` | API (admin-only) | Counts from `scan_jobs` by state, DB latency. The counts are trivially correct — there is no second source. |
| `POST /api/v1/admin/jobs/{id}/retry` | API (admin-only) | Resets a `failed` row to `queued`. |

Worker pods log NATS disconnect / reconnect / closed at WARN — grep for these to see connection flaps.

## Metrics

Every component serves Prometheus metrics at `/metrics` on `:9090` (ADR-0054): the API on its
`metrics` port, the workers on their `health` port. With the chart, `monitoring.enabled: true`
creates a PodMonitor per component (the `ocidex-k8s-agent` chart has its own
`monitoring.enabled`). Turning on `networkPolicy` also requires listing your
scraper in `networkPolicy.ingress.metricsFrom`. Each series carries the Prometheus `job` and `pod`
labels. `target_info` carries `service_name` (`ocidex-api`, `ocidex-scanner-worker`,
`ocidex-enricher-<name>`, ...) and anything set in `monitoring.resourceAttributes`.

| Series | What it tells you |
|---|---|
| `http_server_request_duration_seconds{http_request_method,http_route,http_response_status_code}` | API latency per route pattern. `_count` is the request count; `http_route="unmatched"` is every path no route serves. |
| `ocidex_jobs{queue,state}` | Queue depth: `queued` and `running` rows per queue (`scan`, or an enricher name). Every replica of a worker reports the same value, so aggregate with `max`. |
| `ocidex_jobs_processed_total{queue,outcome}` | Finished jobs: `success`, `retry` (requeued), `permanent_failure` (row is now `failed`). |
| `ocidex_job_duration_seconds{queue}` | Time per job, any outcome. |
| `ocidex_db_pool_connections{pool,state}` | Pool `acquired` / `idle` / `total` / `max` connections. The API has `main` and `background` pools. |
| `ocidex_db_pool_acquires_total{pool,outcome}`, `ocidex_db_pool_acquire_wait_seconds_total{pool}` | Acquires that `waited` for a connection, and the total time spent waiting. |
| `ocidex_nats_publishes_total{subject_class,outcome}` | JetStream publishes: `ok`, `duplicate` (dedup window hit), `error`. Hints that fail are recovered by the poll loop, so errors mean latency, not loss. |
| `ocidex_registry_tags_selected{registry}`, `ocidex_registry_tags_skipped_limit{registry}` | Each registry's last walk (ADR-0053): tags inside the window and tags `tag_limit` left out; the same numbers as the Sources page's Last walk column. Reported by the API; a registry whose last walk failed is absent. |
| `ocidex_retention_pruned_total{class}`, `ocidex_retention_sweep_duration_seconds` | SBOMs the retention sweep deleted (ADR-0056): `window` for registry SBOMs out of their scan window, `newest` for other SBOMs past `RETENTION_KEEP_LAST` or `RETENTION_MAX_AGE`. Reported only by the API replica that holds the sweep; a dry run counts nothing. |
| `go_*`, `process_*` | Go runtime and process stats. |

### Tracing and OTLP export

Tracing is off by default (ADR-0055). Turn it on in the chart with
`monitoring.otel.tracesExporter: otlp` and `monitoring.otel.endpoint` pointing at a collector
(for example Grafana Alloy or the OpenTelemetry Collector, feeding Tempo or Jaeger). The
k8s-agent chart takes the same `monitoring.otel` values. Put collector auth
(`OTEL_EXPORTER_OTLP_HEADERS`) in `existingSecret`, or in the agent's `monitoring.otel.headersSecret`,
never in values. With `networkPolicy.enabled`, list the collector in `monitoring.otel.egress`:
an in-cluster collector is otherwise blocked. `metricsExporter: prometheus,otlp` also pushes
metrics.

The default sampler keeps 10% of new traces. A trace is kept or dropped whole, so one sampled
upload shows its request, its queries, the jobs it queued and every enricher that ran,
including jobs a worker picked up from its poll loop after a lost NATS hint. Log lines inside a
sampled span carry `trace_id`, which links a log line to its trace.

### Suggested alerts

```yaml
groups:
  - name: ocidex
    rules:
      # Incident 1: the queue is growing and nothing drains it.
      - alert: OcidexQueueGrowing
        expr: |
          max by (queue) (ocidex_jobs{state="queued"}) > 0
            and max by (queue) (deriv(ocidex_jobs{state="queued"}[15m])) > 0
        for: 15m
      # Incident 4: jobs are failing for good.
      - alert: OcidexJobPermanentFailures
        expr: |
          sum by (queue) (rate(ocidex_jobs_processed_total{outcome="permanent_failure"}[15m]))
            / sum by (queue) (rate(ocidex_jobs_processed_total[15m])) > 0.1
        for: 15m
      # Matches slowRequestThreshold (internal/api/middleware.go), where requests start
      # logging at WARN.
      - alert: OcidexSlowRoute
        expr: |
          histogram_quantile(0.95,
            sum by (le, http_route) (rate(http_server_request_duration_seconds_bucket[5m]))) > 5
        for: 10m
      # Requests queue for a database connection: raise DATABASE_MAX_CONNECTIONS or find the
      # query holding them.
      - alert: OcidexDBPoolSaturated
        expr: sum by (pool, pod) (rate(ocidex_db_pool_acquire_wait_seconds_total[5m])) > 0.5
        for: 10m
```

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

**Recovery.** Automatic — `runStuckRunningSweep` runs every `SCANNER_STUCK_THRESHOLD/3` (default every 5 min) and moves the row back to `queued` (or to `failed` if `attempts >= SCANNER_MAX_ATTEMPTS`). Both branches record a `stuck: …` `last_error`. Operator action only needed if the same row repeatedly cycles through the sweep — that points at a genuine Syft / registry problem on that specific image.

**A row whose `attempts` climbs while `last_error` stays empty is the worker being killed, not the scan failing.** Nothing reached `FailOrRequeueByID`, so the process died mid-scan: almost always OOMKill on an oversized image, occasionally eviction on `/tmp`. Confirm with `kubectl get pods -l app=ocidex-scanner-worker` (`RESTARTS`, and `lastState.terminated.reason=OOMKilled` in `kubectl describe`). This is not confined to the one row — the OOM takes down every scan sharing that pod. Fix by raising `scannerWorker.resources.limits.memory` if the image is worth scanning, or lowering `SCANNER_MAX_IMAGE_BYTES` so it is rejected from its manifest instead of pulled.

### 4. Failed rows accumulating

**Symptoms.** `state='failed'` count growing. Visible in the admin Jobs tab with the state filter set to `failed`. Each row's `last_error` carries the verbatim error.

**Diagnosis by `last_error`:**

- `manifest unknown` / `404 NotFound` — image was deleted between scheduling and scanning. Nothing to do.
- `connect: connection refused` — registry was unreachable. Either retry once it's back (Retry button on the row) or accept it.
- `syft: …` — actual analysis failure. File a `bd` issue with the row id and digest.
- `stuck: worker did not complete and retries exhausted` — the row cycled through the stuck-running sweep `SCANNER_MAX_ATTEMPTS` times. Usually a specific image Syft can't handle, or one whose scan keeps OOMKilling the worker.
- `image too large to scan: N compressed layer bytes exceeds SCANNER_MAX_IMAGE_BYTES=M` — rejected from its manifest without being pulled. Raise both the ceiling and `scannerWorker.resources.limits.memory` if you want this image, or leave it: the point of the check is that the alternative is an OOMKill loop that also kills unrelated scans.
- `ingest: inserting sbom: ERROR: value "…" is out of range for type integer` — fixed in migration 00073. A pre-00073 database still has the unbounded `sbom.version_major` parse, which raises on any tag whose leading digit run exceeds int4.

**Recovery.** Click Retry on the row to reset it to `queued`. The next poll or hint picks it up with `attempts=0`. A catalog walk will *not* do this for you — since the `InsertScanJob` change, a failed row stays failed until someone retries it, so that a permanently-broken image stops silently re-running every poll interval. For bulk retry: `UPDATE scan_jobs SET state='queued', attempts=0, last_error=NULL WHERE state='failed' AND last_error LIKE '%pattern%'`.

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

### 7. Namespace stuck `Terminating` on `registry-protection` finalizers

**Symptom.** A namespace sits in `Terminating` indefinitely. `kubectl get ns <ns> -o yaml` names the cause in its conditions:

```
NamespaceContentRemaining=True      ociregistries.ocidex.io has N resource instances
NamespaceFinalizersRemaining=True   ocidex.io/registry-protection in N resource instances
NamespaceDeletionContentFailure=False
```

**Cause.** The operator watches only the namespaces in `WATCH_NAMESPACE`. `OCIRegistry` objects outside that scope never reach `handleDeletion`, so their `ocidex.io/registry-protection` finalizer is never removed and the namespace can never drain. Operator health is irrelevant — a perfectly healthy operator still cannot see these objects. This is what a retarget or uninstall leaves behind when the CRs were not drained first.

**Recovery.** Check whether each object ever registered server-side:

```bash
kubectl get ociregistries -n <ns> \
  -o custom-columns='NAME:.metadata.name,REGID:.status.registryID'
```

- `REGID` empty — the object never registered. `handleDeletion` guards its server-side delete with `if cr.Status.RegistryID != ""`, so removing the finalizer by hand is behaviourally identical to what the controller would do, with no orphan rows:

  ```bash
  kubectl patch ociregistry <name> -n <ns> --type=merge \
    -p '{"metadata":{"finalizers":null}}'
  ```

- `REGID` set — **do not patch first.** Delete that registry server-side (UI or `DELETE /api/v1/registries/<id>`), then patch. Patching first strands the registry row with no CR pointing at it.

The namespace drains within seconds of the last finalizer clearing.

## Routine maintenance

### SBOM retention

Nothing deletes stored SBOMs unless retention is on ([ADR-0056](adr/0056-sbom-retention.md)).
Its settings are in [CONFIGURATION.md § SBOM Retention](CONFIGURATION.md#sbom-retention).
Through the chart they're `api.env.retention.*`.

**What it deletes.**
* **Registry SBOMs** go once their tag has left the registry's scan window (`tag_limit`,
  `max_tag_age_days`) at its last successful walk. To store less from a registry, lower
  `tag_limit`. Raising it again brings the tags back: the next walk scans them again.
* **Other SBOMs** (uploads, auto-ingested images, direct scans) keep the newest
  `RETENTION_KEEP_LAST` versions per artifact and flavor in each namespace, and optionally
  nothing older than `RETENTION_MAX_AGE`.

**What it never deletes.**
* The newest version of each artifact, and its highest semver version.
* Anything running in a registered cluster.
* Anything ingested in the last 24 hours or with an enrichment job queued or running.

**Turning it on.**
1. Set `RETENTION_MODE=dry-run`. Each sweep logs a `retention sweep` line with `window` and
   `newest` counts, and writes a `retention.swept` audit entry. It deletes nothing.
2. When the counts look right, set `RETENTION_MODE=on`. The first sweep works through the
   backlog in batches of `RETENTION_BATCH`, with a short pause between them.
   `ocidex_retention_pruned_total` shows its progress.

**Disk.** Postgres reuses the space deleted rows leave, but doesn't return it to the
filesystem. After a large first sweep, reclaim it in a maintenance window with
`VACUUM FULL` (it locks each table while it rewrites it), or with `pg_repack` online.

**Around a sweep.** List pages catch up at the next rollup refresh, within 15 minutes.
Vulnerabilities only the pruned SBOMs had are dropped at the end of the vuln-worker's next
pass. A pruned SBOM's URL returns 404, and the changelog diffs across the gap.

### Retargeting or uninstalling the operator

The `registry-protection` finalizer is a promise that some operator watching that namespace will remove it. Changing `watchNamespace` or uninstalling while `OCIRegistry` objects still exist in the watched namespace breaks that promise and strands them (incident 7 above). Both procedures below avoid it; pick by whether the registries need to stay alive.

**Draining (the registries are going away):**

```bash
kubectl delete ociregistry --all -n <old-ns>   # operator still watching
kubectl get ociregistries -n <old-ns>          # wait for: No resources found
# only now change watchNamespace, or `helm uninstall`
```

**Live migration (the registries must keep running):** `watchNamespace` is comma-separated, so the old and new scopes can overlap for the duration of the move.

1. `helm upgrade --set watchNamespace=<old-ns>,<new-ns>` — the operator now reconciles both.
2. Recreate the CRs in `<new-ns>`, then delete them from `<old-ns>`. The finalizers release normally because `<old-ns>` is still watched.
3. Confirm `kubectl get ociregistries -n <old-ns>` is empty.
4. `helm upgrade --set watchNamespace=<new-ns>` to drop the old scope.

The operator logs its live scope as `watch_namespaces` at startup — check there first when the deployed value is in doubt.

### Rotating the credential encryption key

Registry credentials are encrypted with a key from `DATA_ENCRYPTION_KEYS`
([ADR-051](adr/0051-credential-encryption-at-rest.md)). Every listed key decrypts;
`DATA_ENCRYPTION_ACTIVE_KEY` encrypts. A stored value names the key that sealed it
(`enc:v1:<key-id>:...`), so a rotation is online:

1. Generate a key: `openssl rand -base64 32`.
2. Add it to `DATA_ENCRYPTION_KEYS` in the Secret alongside the old one
   (`old:<b64>,new:<b64>`) and set `DATA_ENCRYPTION_ACTIVE_KEY=new`.
3. Roll out. New writes use `new`, and every process can still read `old`. The chart's
   migrate hook Job runs `ocidex migrate encrypt-secrets` after `migrate up`, which
   re-seals every value under `new`. Outside the chart, run it yourself (`--dry-run` to
   preview). It is idempotent.
4. Confirm the job's output reports `0 rotated` on a second run, or check that no value
   still names the old key:
   `SELECT count(*) FROM registry WHERE auth_token LIKE 'enc:v1:old:%' OR webhook_secret LIKE 'enc:v1:old:%';`
5. Remove `old` from `DATA_ENCRYPTION_KEYS` and roll out again.

Removing a key before step 4 makes the values it sealed unreadable: those registries
fail on read until their credentials are re-entered.

**First enablement** follows the same path: set one key, roll out, and `encrypt-secrets`
seals the existing plaintext. Until it runs, plaintext rows keep working.

**Losing every key** makes stored credentials unrecoverable. Nothing else is affected.
Configure a new key, then re-enter each registry's auth token and regenerate its webhook
secret (`POST /api/v1/registries/{id}/webhook-secret`) and update the sender. Back up the
key separately from the database: a backup holding both defeats the encryption.

- **Backups**: see [Backup and restore](#backup-and-restore). Postgres is the only state that needs one.
- **Tuning concurrency** — `SCANNER_MAX_CONCURRENCY` directly maps to active worker goroutines. Watch pod memory: Syft is the cost. There is no longer a `SCANNER_MAX_ACK_PENDING` to tune in lockstep.

### Backup and restore

**What to back up.**

| Data | Back up? | Why |
|---|---|---|
| Postgres database | **Yes** | Everything OCIDex knows: SBOMs, artifacts, users, sessions, API keys, registries, clusters, scan and enrichment state. |
| `SESSION_SECRET` | **Yes**, separately | Signs session and OAuth state cookies. A restore with a different secret signs everyone out, which is safe but disruptive. |
| `DATA_ENCRYPTION_KEYS` | **Yes**, separately | Decrypts stored registry credentials ([Rotating the credential encryption key](#rotating-the-credential-encryption-key)). Without it, registries need their tokens re-entered. Never store it with the database backup. |
| OAuth client secrets (`GITHUB_CLIENT_SECRET`, `OIDC_CLIENT_SECRET`) | **Yes**, separately | Can be reissued by the identity provider, at the cost of an outage. |
| NATS volume | No | No data: workers claim jobs from Postgres, and a lost hint costs at most one poll interval (`SCANNER_POLL_INTERVAL`). |
| grype database volume | No | Downloaded again at startup. |
| Enrichment results | Inside the database | Restored with it. Anything lost can be re-run, since enrichment is derived from the SBOM and the registry. |

**CloudNativePG: continuous backup.** Configure WAL archiving and scheduled base backups on
the `Cluster`, to S3 or anything S3-compatible (MinIO on a NAS works):

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: ocidex-pg
spec:
  backup:
    retentionPolicy: 30d
    barmanObjectStore:
      destinationPath: s3://ocidex-backups/ocidex-pg
      endpointURL: https://minio.example:9000      # omit for AWS S3
      s3Credentials:
        accessKeyId: { name: ocidex-pg-backup, key: ACCESS_KEY_ID }
        secretAccessKey: { name: ocidex-pg-backup, key: SECRET_ACCESS_KEY }
      wal: { compression: gzip }
---
apiVersion: postgresql.cnpg.io/v1
kind: ScheduledBackup
metadata:
  name: ocidex-pg-daily
spec:
  schedule: "0 0 3 * * *"   # CNPG's cron has a seconds field
  backupOwnerReference: self
  cluster: { name: ocidex-pg }
```

CNPG 1.26 and later move object-store backups to the Barman Cloud plugin. The fields are the
same, set on an `ObjectStore` resource instead. Check that backups are completing with
`kubectl get backups`, and that WAL archiving is healthy with
`kubectl cnpg status ocidex-pg` ("Continuous Backup status").

**Without CNPG: `pg_dump`.** A nightly logical dump is enough for most installs, since
OCIDex can tolerate losing a day of ingests:

```bash
pg_dump "$DATABASE_URL" -Fc --no-owner -f ocidex-$(date +%F).dump
```

**Restore.**
1. **Stop writers.** Scale the API, scanner-worker, enricher workers and vuln-worker to 0. If
   the operator and k8s-agent can't reach the API, they retry on their own.
   ```bash
   kubectl scale deploy -n <ns> -l app.kubernetes.io/part-of=ocidex --replicas=0
   ```
2. **Restore the database.**
   * **CNPG:** create a new `Cluster` with `spec.bootstrap.recovery` pointing at the backup,
     optionally with `recoveryTarget.targetTime` for point-in-time recovery. Then point
     `DATABASE_URL` at its `-rw` service. Restoring into a new cluster leaves the old one to
     fall back on.
   * **`pg_dump`:** into an empty database owned by the application role:
     ```bash
     pg_restore -d "$DATABASE_URL" --no-owner --exit-on-error ocidex-YYYY-MM-DD.dump
     ```
3. **Check the schema.** `ocidex migrate status` must list every migration as applied. If the
   backup predates the running version, `ocidex migrate up` (or the chart's `migrate` Job on
   the next upgrade) brings it forward. Never run an older image against a newer schema.
4. **Restore secrets.** Use the same `SESSION_SECRET` and `DATA_ENCRYPTION_KEYS` the backup was
   taken with.
5. **Start in order.** API first (wait for `/ready`), then the scanner-worker and enricher
   workers, then the vuln-worker. Jobs that were `running` at backup time are reclaimed once
   their stuck threshold passes (incident 3).
6. **Verify.** Compare counts against the last known values, and sign in:
   ```sql
   SELECT count(*) AS sboms, count(DISTINCT artifact_id) AS artifacts FROM sbom;
   SELECT max(created_at) FROM sbom;   -- the newest ingest the backup holds
   ```

SBOMs ingested after the backup are gone. CI re-ingests on its next build, and registry walks
re-scan their windows on the next poll.

**Drill (2026-10-23, ocidex-xxee.7).** Postgres 18.6, `pg_dump`/`pg_restore`, 200 SBOMs and
40k components from `cmd/loadgen`. The dump took 1s and was 5.1 MB; the restore took 4s.
After the restore:
* `migrate status` showed all 86 migrations applied.
* Row counts and an `md5` over every SBOM id and digest were identical.
* The same API key authenticated, and the API listed all 10 artifacts.

The commands are in the issue's notes.

### Backfilling rows stored before ingest derived them

`ocidex migrate backfill` re-derives, from data already in the database, the columns that
ingest writes today but did not always write:

| Step | Column | Rows it selects |
|---|---|---|
| flavor | `sbom.flavor` | SBOMs ingested before flavor detection |
| purl | `component.purl` | components with a version whose purl has none |
| provenance | `component.layer_id`, `found_by`, `source_*`, `file_path` | components with a bom-ref and no `file_path` (pre-00072) |

It is idempotent. A row whose SBOM records no location keeps a NULL `file_path`, so the
provenance step re-reads those SBOMs on every run without changing them. An SBOM whose
`raw_bom` does not decode is logged, counted as `errored` and skipped. A database error stops
the run, and re-running resumes safely.

It reads `raw_bom` one SBOM at a time, but over a large corpus it takes a while, so run it
by hand, once, outside the chart's migrate hook, using the API image with the chart's
`existingSecret`:

```bash
kubectl -n <ns> run ocidex-backfill --rm -i --restart=Never \
  --image=ghcr.io/pfenerty/ocidex-api:<version> \
  --overrides='{"spec":{"containers":[{"name":"ocidex-backfill","image":"ghcr.io/pfenerty/ocidex-api:<version>","command":["/ocidex","migrate","backfill"],"envFrom":[{"secretRef":{"name":"<existingSecret>"}}]}]}}'
```

It prints one line per step: `backfill <step>: N updated, N unchanged, N errored`.

## Postgres on CloudNativePG — migration playbook

The production Postgres deployment is being moved from a hand-managed `StatefulSet` (`postgres:15.4-alpine`, formerly in `ocidex/k8s/base/` — that tree has since been removed, see step 7) to a CloudNativePG (CNPG) `Cluster` (declared in `homelab/talos-cluster/flux/apps/ocidex/postgres.yaml`). Tracked under `ocidex-ujj.78`. ADR: see commit history + the homelab `talos-cluster/flux/apps/cnpg/`.

### Why

- Auto-tuning of `shared_buffers`, `work_mem`, `effective_cache_size`, `max_connections` from the declared `resources` block. No more remembering Postgres tuning formulas.
- Continuous WAL archival + PITR available by setting `spec.backup` once a target is provisioned (NAS MinIO, S3, NFS).
- Built-in failover when a second worker node justifies a replica.
- Managed major-version upgrades via `spec.imageName` bumps.

### Pre-flight

1. Verify the existing StatefulSet's PVC is healthy: `kubectl -n ocidex get pvc`.
2. Take a snapshot or `pg_dump` to the NAS for paranoia. CNPG's `initdb.import.monolith` does pg_dump/restore internally, but having an out-of-band copy makes the rollback story simpler.
3. Confirm cluster has spare memory for both Postgres pods to coexist briefly during the import (~2 GiB extra during the import window).

### Cutover sequence

1. **Create the CNPG app-user Secret locally.** The Cluster CR's bootstrap references `Secret/ocidex-pg-app` which doesn't yet exist. CNPG requires the keys `username` and `password` literally — they are not configurable. Use the template + one-liner that lives at `homelab/talos-cluster/flux/apps/ocidex/postgres-app-secret.template.yaml`:

    ```bash
    cd homelab/talos-cluster/flux/apps/ocidex
    PW=$(SOPS_AGE_KEY_FILE=../../../../age.key \
         sops -d --extract '["stringData"]["POSTGRES_PASSWORD"]' secrets.enc.yaml)
    sed "s|<PLACEHOLDER>|$PW|" postgres-app-secret.template.yaml \
      > postgres-app-secret.enc.yaml
    SOPS_AGE_KEY_FILE=../../../../age.key \
      sops -e -i postgres-app-secret.enc.yaml
    unset PW
    ```

    Verify the file is encrypted (`head postgres-app-secret.enc.yaml` should show `ENC[…]`).

2. **Commit + push the homelab change.** Flux installs the CNPG operator, creates the `ocidex-pg` Cluster, and CNPG runs `initdb.import` against the legacy StatefulSet's `postgres` Service. Watch:

    ```bash
    kubectl -n cnpg-system get pods -w           # operator is up
    kubectl -n ocidex get cluster ocidex-pg -w    # imports → Cluster in healthy state
    kubectl -n ocidex get pods                    # ocidex-pg-1 reaches Ready
    ```

    Initial import takes a couple of minutes for the ocidex schema.

3. **Verify the new cluster has the data.** Spot-check row counts:

    ```bash
    kubectl -n ocidex exec -it ocidex-pg-1 -- \
      psql -U ocidex -d ocidex -c "SELECT count(*) FROM scan_jobs; SELECT count(*) FROM sbom;"
    ```

    Compare to the same query against the legacy pod (`postgres-0`). Counts should match exactly — no writes have been routed to the new cluster yet.

4. **Update `DATABASE_URL` in `ocidex-secrets` to point at the new RW service.** Edit `homelab/talos-cluster/flux/apps/ocidex/secrets.enc.yaml` to change `host=postgres` → `host=ocidex-pg-rw` (port + dbname stay 5432 / `ocidex`):

    ```bash
    SOPS_AGE_KEY_FILE=../../../../age.key sops secrets.enc.yaml
    # change the DATABASE_URL line, save, exit
    ```

    Commit + push. Flux updates the Secret.

5. **Roll the apps so they pick up the new env var.** Secrets don't auto-restart pods:

    ```bash
    kubectl -n ocidex rollout restart deploy/ocidex-api \
      deploy/ocidex-scanner-worker deploy/ocidex-oci-metadata-worker \
      deploy/ocidex-git-worker deploy/ocidex-user-enricher-worker \
      deploy/ocidex-provenance-worker deploy/ocidex-vuln-worker
    ```

    Wait for rollouts to complete. Tail a worker log; the `database connected` line should appear and processing should resume against the new Postgres.

6. **Verify** for a few minutes that scans are succeeding against the new DB and no `connection refused` errors appear.

### Post-cutover cleanup (separate PR)

7. ~~In the ocidex repo, delete the in-repo Postgres manifests and deregister them from the Kustomize overlays.~~ **Done.** The whole `k8s/` tree was removed in `e1bf40f` when the deployment moved to Helm-only; `charts/ocidex` deliberately renders no database (ADR-031 — Postgres is a platform concern owned by the homelab repo's CNPG `Cluster`). Nothing to delete here.

8. The legacy PVC has retention policy `Retain`, so the old data sticks around. After a grace period (1–2 weeks), `kubectl -n ocidex delete pvc data-postgres-0` to reclaim the storage.

### Rollback

If anything looks off before step 5:

- The legacy `postgres` StatefulSet is still running and still has the original data (CNPG's import is non-destructive — it only reads from the source).
- Revert the homelab commits (`git revert`), push. Flux removes the CNPG Cluster CR; apps continue against the legacy Postgres uninterrupted.
- Drop the new app-user Secret on principle: `kubectl -n ocidex delete secret ocidex-pg-app`.

If a problem surfaces after step 5:

- Reverse step 4 (DATABASE_URL back to `host=postgres`).
- Reverse step 5 (`kubectl rollout restart …` again).
- Diagnose the new cluster, then re-attempt.
