# ADR 0027: Ephemeral Job Contract (--once Mode)

**Status:** Accepted  
**Date:** 2026-06-06

## Context

Both `scanner-worker` and `enrichment-worker` run as long-lived daemons in the production cluster, consuming work from NATS JetStream. For on-demand or K8s Job use cases (triggered by a CI pipeline, a CLI call, or a Tekton Task), the same binary needs to process a single unit of work and exit cleanly so the Job controller can track completion.

A separate binary would duplicate all startup logic. A flag that puts the existing binary into a "run once and exit" mode is cheaper and keeps the two modes in sync.

## Decision

Each worker supports a `--once` flag. When set:

1. The worker initializes the same dependencies as daemon mode (DB pool, NATS connection if needed, enricher registry, etc.).
2. It reads the target from environment variables, processes exactly one item, emits structured lifecycle log events, and exits with code 0 on success or non-zero on failure.
3. No NATS subscription is created; the job is entirely driven by env vars.

### scanner-worker --once

| Env var | Required | Description |
|---------|----------|-------------|
| `SCAN_IMAGE` | Yes | Full image reference (`registry/repo@sha256:...` or `registry/repo:tag`) |
| `SCAN_REGISTRY_ID` | No | UUID of the OCIDex registry record to associate the SBOM with |
| `SCAN_INSECURE` | No | `"true"` to skip TLS verification |
| `SCAN_AUTH_USERNAME` | No | Registry auth username |
| `SCAN_AUTH_TOKEN` | No | Registry auth token/password |

**Log events:** `scan started` (image, repo, digest, tag) → `scan complete` (image, duration_ms) → `sbom ingested` (sbom_id, component_count).

### enrichment-worker --once

| Env var | Required | Description |
|---------|----------|-------------|
| `ENRICH_SBOM_ID` | Yes | UUID of the SBOM to enrich |

**Log events:** `enrichment started` (sbom_id) → `enrichment complete` (sbom_id, duration_ms).

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — item processed |
| 1 | Fatal startup error (bad config, DB unreachable) |
| 1 | Processing error (scan failed, SBOM ingest rejected, enrichment failed) |

Non-zero exit causes a K8s Job to retry according to its `backoffLimit`. The structured log entry immediately before exit carries the error details.

## Consequences

- K8s Jobs, Tekton Tasks, and CLI scripts can use the same binaries as the daemon workers.
- Daemon and --once code paths share all initialization and processing logic; only the dispatch loop is skipped.
- Adding new env vars to `--once` mode is the only extension point; no plugin or config-file mechanism is needed for single-item jobs.
- The caller is responsible for ensuring idempotency (re-ingesting the same SBOM is safe; re-enriching an already-enriched SBOM upserts the result).

## Key Files

- `cmd/scanner-worker/main.go` — `runOnce`, env var parsing
- `cmd/enrichment-worker/main.go` — `runEnrichOnce`, env var parsing
- `docs/EPHEMERAL_JOBS.md` — operator runbook
