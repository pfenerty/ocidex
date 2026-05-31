# SBOM Ingestion Pipeline

Reference document for the full ingest lifecycle: entry paths, service internals, async enrichment, and query-time metadata resolution.

---

## 1. Overview

```
Direct API Upload ──────────────────────────────┐
                                                │
Registry Catalog Scan ──► ScanRequest ──► Dispatcher.process() ──► service.Ingest()
                                         ▲                                │
Registry Webhook ────────► ScanRequest ──┘                          tx.Commit()
                                         ▲                                │
NATS Worker ────────────► ScanRequest ──┘                     event.SBOMIngested
                                                                          │
                                                               async OCI enricher
                                                                          │
                                                              enrichment[oci-metadata]
                                                                          │
                                                              Query (COALESCE)
                                                         oci-metadata > user fallback
```

---

## 2. Entry Paths

### Path A: Direct API Upload

**Endpoint:** `POST /api/v1/sbom?version=&architecture=&build_date=`

**Handler:** `internal/api/sbom.go` → `IngestSBOM()`
**Input type:** `internal/api/types.go` → `IngestSBOMInput`

Flow:
1. Decode CycloneDX JSON body.
2. `validateBOM()` — checks `bomFormat`, `specVersion`, and at least one component present.
3. Construct `service.IngestParams{Version, Architecture, BuildDate}` from query params.
4. Call `service.Ingest()`.

Query params take priority over anything extracted from the BOM (see §3 for the full resolution chain).

---

### Path B: Registry Catalog Scan

**Trigger:** `POST /api/v1/registries/{id}/scan` (admin) — runs async; periodic scans are a planned future feature.

**Code:** `internal/api/registry.go` → `ScanRegistry()` → `walkRegistryCatalog()`

Walk sequence:
1. `ociListCatalog()` — `GET /v2/_catalog` → list of repository names.
2. Filter by `reg.MatchesRepository(repo)`.
3. `ociListTags()` — `GET /v2/{repo}/tags/list`.
4. Filter by `reg.MatchesTag(tag)`.
5. `ociHeadManifest()` — `HEAD /v2/{repo}/manifests/{tag}` → digest + mediaType.

**Single-arch image** (`mediaType` is a plain manifest):
- `ociGetImageMetadata()`:
  - `GET /v2/{repo}/manifests/{digest}` → parse `annotations["org.opencontainers.image.created"]` for build date.
  - `GET /v2/{repo}/blobs/{config.digest}` → parse `architecture` and `created` (fallback when annotation absent).
- Submit `ScanRequest{RegistryURL, Insecure, Repository, Digest, Tag, Architecture, BuildDate}`.

**Multi-arch image** (`mediaType` is an OCI index or Docker manifest list):
- `ociExpandIndex()` — `GET /v2/{repo}/manifests/{indexDigest}` → parse `manifests[]`.
  - Skip entries where `platform.os` is empty or `"unknown"` (attestations, provenance records).
- Per platform entry: `ociGetImageMetadata()` as above.
  - `arch` comes from the index entry (`platform.architecture`); index entry is authoritative. Falls back to config blob only if the index entry is empty.
- Submit one `ScanRequest` per platform, each with its own digest, arch, and build date.

---

### Path C: Registry Webhook

**Endpoint:** `POST /api/v1/webhooks/{registryID}` (public — no auth middleware; matched by prefix in router)

**Handler:** `internal/api/webhook.go` → `HandleRegistryWebhook()`

Flow:
1. Look up registry by `registryID`. Return 404 if not found; 503 if disabled.
2. Validate `Authorization: Bearer <secret>` if `reg.WebhookSecret` is set.
3. Check `in.Body.MediaType` — only `application/vnd.oci.image.manifest.v1+json` and `application/vnd.docker.distribution.manifest.v2+json` are scannable. Index types and unknown types are silently ignored.
4. `reg.MatchesImage(name, reference)` — apply repository/tag filter patterns.
5. Submit `ScanRequest{RegistryURL, Insecure, Repository: name, Digest: digest, Tag: reference}`.

**Note:** `Architecture` and `BuildDate` are **not set** on the webhook path. The webhook payload does not include them. They will be resolved at `service.Ingest()` time from Syft BOM properties (e.g., `syft:image:config.Architecture`, `syft:image:labels:org.opencontainers.image.created`). If those properties are also absent, the container SBOM will be rejected with 422.

---

### Path D: Dispatcher (scan execution)

**Code:** `internal/scanner/dispatcher.go` → `Dispatcher.process()`

The dispatcher is an in-process worker pool. Paths B, C, and E all funnel `ScanRequest`s through it.

Flow:
1. `scanner.Scan(ctx, req)` — invokes Syft library against `{registryURL}/{repository}@{digest}`; returns raw CycloneDX JSON.
2. Decode CycloneDX JSON into `*cdx.BOM`.
3. Call `service.Ingest(bom, raw, service.IngestParams{Version: req.Tag, Architecture: req.Architecture, BuildDate: req.BuildDate})`.

`Architecture` and `BuildDate` from the `ScanRequest` are passed directly as `IngestParams`. If they are empty (webhook path), the service falls through to BOM property extraction.

---

### Path E: Outbox-pattern scan pipeline (Postgres-as-queue)

**Publish:** `internal/scanner/nats_submitter.go`
**Consume:** `internal/scanner/nats_hint.go`
**ADR:** `docs/adr/0024-outbox-pattern-for-scan-queue.md`

The `scan_jobs` row is the single source of truth for queued work. NATS carries only `{id}` hints for fast worker wakeup, and is never load-bearing for durability or retry.

**Producer (`NATSSubmitter.Submit`).**

1. `jobSvc.Enqueue` inserts a `scan_jobs` row with `state='queued'` and `nats_msg_id=registry_id@digest` (a row-level idempotency key under its legacy column name — same `(registry, digest)` pair publishing twice collapses to one row via the column's UNIQUE constraint).
2. Best-effort `JS.Publish` of `{"id":"<uuid>"}` to `ocidex.scan.hint`. Publish failure is logged but not fatal; the worker's DB poll loop will pick the row up.

**Consumer (`NATSHintExtension`).**

- Durable JetStream consumer `scanner-hint` on `ocidex.scan.hint`, `AckPolicy=AckExplicit`, `MaxDeliver=1` (NATS does not retry — the DB owns retry).
- `handleHint`: ack immediately on receipt, decode `{id}`, push id to a bounded `hints` channel.
- N worker goroutines (`N = SCANNER_MAX_CONCURRENCY`) each loop on `select { hint | pollTicker }`. On hint: `ClaimByID(id)`; on poll: `ClaimNext()`. Either path returns the job with registry credentials joined in (a single `UPDATE … RETURNING` with `FOR UPDATE SKIP LOCKED`).
- On `ProcessOne` success: `FinishByID(id, sbomID)` — `state → succeeded`.
- On `ProcessOne` failure: `FailOrRequeueByID(id, err, SCANNER_MAX_ATTEMPTS)` — increments `attempts`; transitions `→ queued` for retry or `→ failed` when the budget is exhausted.

**Stuck-running sweep.** `runStuckRunningSweep` calls `RequeueStuckRunning` every `SCANNER_STUCK_THRESHOLD/3`. Any `running` row whose `last_attempt_at` is older than the threshold goes back to `queued` (or `failed` if retries are exhausted). This replaces the orphan reconciler — under the outbox model there is no NATS-aware reconciliation.

#### Knobs

| Var | Default | Purpose |
|---|---|---|
| `SCANNER_MAX_CONCURRENCY` | 10 (prod: 1) | Number of worker goroutines per pod. Bounds memory: Syft is the heavyweight. |
| `SCANNER_POLL_INTERVAL` | 30s | DB poll cadence for the queue-drain fallback. Lower = lower latency when NATS hints fail; higher = lower DB load. |
| `SCANNER_STUCK_THRESHOLD` | 15m | A `running` row idle longer than this is presumed dead and requeued. |
| `SCANNER_MAX_ATTEMPTS` | 3 | Retry budget per row. Beyond this, `FailOrRequeueByID` marks `failed`. |

`SCANNER_MAX_ACK_PENDING`, `SCANNER_WORKERS`, `SCANNER_QUEUE_SIZE` are gone — they existed only to coordinate the dual-write design.

#### Failure modes

| Event | Recovery |
|---|---|
| NATS pod down | Poll loop drains the queue at `SCANNER_POLL_INTERVAL` latency. |
| NATS PVC lost | Same as above. No work loss — rows are in Postgres. |
| Publish fails after row insert | Poll loop picks up within `SCANNER_POLL_INTERVAL`. |
| Worker crashes mid-scan | Stuck-running sweep requeues the row after `SCANNER_STUCK_THRESHOLD`. |
| Two workers race the same hint | One `ClaimByID` claim succeeds, the other returns no row and no-ops. |
| Duplicate enqueue (same registry@digest) | `nats_msg_id` UNIQUE → producer's `Enqueue` errors with PG `23505`; submitter treats as no-op. |

#### Layer-cache (future work)

Each scan re-pulls all image layers — Stereoscope keeps a per-job tmpdir but there is no cross-job cache. For the Pi4 deployment this is acceptable; for higher-throughput targets, a shared volume mount (or registry mirror in front of the scanner) would amortise layer pulls. Not implemented; the redesign is significant and the current bottleneck is Syft CPU, not registry bandwidth.

---

## 3. `service.Ingest()` Internals

**File:** `internal/service/sbom.go`

### Pre-transaction: digest validation

If a `DigestValidator` is configured, container SBOMs are validated against the registry before the transaction begins. Rejects any digest that points to a manifest list (image index) rather than a single image manifest.

### Idempotency check

`extractDigestFromBOM()` pulls the digest from the BOM:
- `metadata.component.name` suffix `@sha256:...`
- `metadata.component.version` prefix `sha256:`

If a digest is found, `GetSBOMByDigest()` is called. On hit → return the existing SBOM ID. On miss (or error other than `pgx.ErrNoRows`) → proceed. The UNIQUE index on `sbom.digest` is the final backstop.

### `resolveArtifact()`

- Strips the `@sha256:...` digest suffix from `metadata.component.name` so that the same image (with different digests) resolves to one artifact row.
- Captures the digest for indexing.
- Container SBOMs without any digest → immediate 422.
- `UpsertArtifact()` by `(type, name, group_name)`.

### Metadata resolution

Called in order; first non-empty value wins:

| Field | 1st priority | 2nd priority | 3rd priority | 4th priority |
|---|---|---|---|---|
| `subject_version` | `params.Version` | `mc.Version` (if not a `sha256:` digest) | `syft:image:labels:org.opencontainers.image.version` | `syft:image:labels:org.label-schema.version` |
| `architecture` | `params.Architecture` | `syft:image:config.Architecture` | `syft:image:labels:org.opencontainers.image.architecture` | — |
| `build_date` | `params.BuildDate` | `syft:image:labels:org.opencontainers.image.created` | `syft:image:labels:org.label-schema.build-date` | — |

Properties are searched in `metadata.component.properties` first, then `metadata.properties`.

**Syft note:** `syft:image:config.Architecture` is emitted from the image config blob's `architecture` field. `syft:image:labels:*` properties come from image **config labels** (not OCI manifest annotations). For images that only set version/created in manifest annotations (not config labels), `params.*` from the registry walk is the reliable source.

**Trivy note:** Trivy emits `aquasecurity:trivy:Labels:org.opencontainers.image.version` — this is also checked for `subject_version`.

### Mandatory validation (container SBOMs only)

After resolution, all three fields must be non-empty:
- `subject_version`
- `architecture`
- `build_date`

Missing fields → 422 listing which fields are absent.

### Transaction contents

Within a single transaction:
1. `InsertSBOM()` — stores raw BOM JSON, `subject_version`, digest, artifact link.
2. `UpsertEnrichment()` with `enricher_name="user"`, `status="success"` — writes `{architecture, created, imageVersion}` so metadata is immediately visible in queries before the async OCI enricher runs.
3. `insertComponents()` — recursive, handles nested components.
4. `insertDependencies()`.
5. Commit.

### Post-commit: event publish

After successful commit, `event.SBOMIngested` is published with `{SBOMID, ArtifactType, ArtifactName, Digest, SubjectVersion}`. This triggers the async OCI enrichment pipeline.

---

## 4. Async OCI Enrichment

**File:** `internal/enrichment/oci/oci.go`

Triggered by `event.SBOMIngested`. Runs in a separate goroutine/worker pool.

This enricher **does not read the Syft BOM**. It contacts the OCI registry directly using `google/go-containerregistry`, pulling the config blob and manifest for the stored `artifactName@digest`. It is an independent second opinion on the same image, and its output supersedes the Syft-derived "user" enrichment at query time.

### `CanEnrich()`

Only processes artifacts with `type == "container"` and a non-empty digest.

### `Enrich()` flow

1. Construct image ref as `artifactName@digest`.
2. `remote.Get()` via `google/go-containerregistry`.
3. Reject if `desc.MediaType.IsIndex()` — ingest-time validation should have prevented this.
4. Fetch:
   - `img.ConfigFile()` → `architecture`, `os`, `created`, `Labels`
   - `img.Manifest()` → `annotations`
   - `fetchParentIndexAnnotations()` (best-effort, 5s timeout) — looks up the tag as an image index to retrieve index-level annotations. Returns nil on any error.

### `extractMetadata()` priority

For each field, the priority across sources is: **manifest annotations > config labels > index annotations**.

| Field | Source |
|---|---|
| `architecture` | Config blob `architecture` only (not in annotations) |
| `os` | Config blob `os` only |
| `created` | Config blob `created` (if non-zero); else `org.label-schema.build-date` across all sources |
| `imageVersion` | `org.opencontainers.image.version`, then `org.label-schema.version`, then `labels["version"]` |
| `sourceUrl` | `org.opencontainers.image.source`, then `org.label-schema.vcs-url` |
| `revision` | `org.opencontainers.image.revision`, then `org.label-schema.vcs-ref` |
| `description`, `url`, `documentation`, `vendor`, `title` | OCI standard annotations > label-schema equivalents |

Result is stored as `enricher_name="oci-metadata"`, `status="success"`. The richer set of fields (source URL, VCS revision, description, OS, etc.) supplements what the "user" enricher stores.

---

## 5. Query-time COALESCE

Both `ListSBOMsByArtifact` (`db/queries/artifact.sql`) and `GetComponentVersions` (`db/queries/search.sql`) join two enrichment rows:

```sql
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user'          AND u.status = 'success'
```

Selected as:

```sql
COALESCE(e.data->>'architecture', u.data->>'architecture') AS architecture
COALESCE(e.data->>'imageVersion', u.data->>'imageVersion') AS image_version
(COALESCE(e.data->>'created',     u.data->>'created'))::timestamptz AS build_date
```

`oci-metadata` is authoritative. `user` is the immediate fallback populated synchronously at ingest time, so queries never return empty metadata while enrichment is pending.

---

## 6. Metadata Authority Hierarchy (end-to-end)

```
Ingest time:
  params.* (from query params or ScanRequest)
    > BOM properties (syft:image:config.*, syft:image:labels:*)
    > (absent → 422 for container SBOMs)

Written to:
  sbom.subject_version
  enrichment[user].{architecture, imageVersion, created}

Async (after commit):
  OCI enricher → enrichment[oci-metadata].{architecture, created, imageVersion, ...}

Query time:
  enrichment[oci-metadata] > enrichment[user]
```

---

## 7. Key Files

| Area | File |
|---|---|
| Direct API handler | `internal/api/sbom.go` |
| API input types | `internal/api/types.go` |
| Service logic | `internal/service/sbom.go` |
| Registry walk + OCI helpers | `internal/api/registry.go` |
| Webhook handler | `internal/api/webhook.go` |
| Dispatcher (worker pool) | `internal/scanner/dispatcher.go` |
| Scanner + ScanRequest struct | `internal/scanner/scanner.go` |
| NATS publish | `internal/scanner/nats_submitter.go` |
| NATS consume | `internal/scanner/nats_extension.go` |
| OCI enricher | `internal/enrichment/oci/oci.go` |
| COALESCE queries | `db/queries/artifact.sql`, `db/queries/search.sql` |
