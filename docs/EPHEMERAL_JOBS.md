# Ephemeral Jobs (--once Mode)

`scanner-worker` and every per-enricher worker support a `--once` flag that processes a single item and exits. This is the intended mode for Kubernetes Jobs, Tekton Tasks, and CLI-triggered one-shot scans.

See [ADR 0027](adr/0027-ephemeral-job-contract.md) for the design rationale.

---

## scanner-worker --once

Scans a single image reference, generates a CycloneDX SBOM via Syft, and ingests it into OCIDex.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SCAN_IMAGE` | Yes | Full image reference — `registry/repo@sha256:digest` or `registry/repo:tag` |
| `SCAN_REGISTRY_ID` | No | UUID of the OCIDex registry record to associate the SBOM with |
| `SCAN_INSECURE` | No | `true` to skip TLS verification for the target registry |
| `SCAN_AUTH_USERNAME` | No | Registry auth username |
| `SCAN_AUTH_TOKEN` | No | Registry auth token or password |
| `LOG_LEVEL` | No | `debug`, `info` (default), `warn`, `error` |
| `NATS_URL` | No | Not used in --once mode; the scan path is synchronous |

### Usage

```bash
SCAN_IMAGE="ghcr.io/myorg/myapp@sha256:abc123..." \
SCAN_REGISTRY_ID="3821c2b4-3689-431e-bab9-7f5248e53b87" \
DATABASE_URL="postgres://..." \
  ./bin/scanner-worker --once
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | SBOM generated and ingested successfully |
| 1 | Fatal error (bad config, DB unreachable, scan failed, ingest rejected) |

### K8s Job Example

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: scan-myapp-v1
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: scanner
          image: ghcr.io/pfenerty/ocidex/scanner-worker:latest
          args: ["--once"]
          env:
            - name: SCAN_IMAGE
              value: "ghcr.io/myorg/myapp:v1.0.0"
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: ocidex-secrets
                  key: DATABASE_URL
```

---

## `<name>-worker --once`

Each per-enricher worker (`oci-metadata-worker`, `git-worker`, `user-enricher-worker`,
`provenance-worker`) enriches an already-ingested SBOM with its own enricher and exits.
The flag is implemented once, in `internal/worker/enrichment.RunOnce`, so the contract
below is identical for all of them.

Note that `--once` runs only the calling binary's enricher and does **not** chain to
dependents (ADR-035) — run each worker you need in turn.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `ENRICH_SBOM_ID` | Yes | UUID of the SBOM to enrich |
| `LOG_LEVEL` | No | `debug`, `info` (default), `warn`, `error` |

### Usage

```bash
ENRICH_SBOM_ID="a1b2c3d4-..." \
DATABASE_URL="postgres://..." \
  ./bin/oci-metadata-worker --once
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Enrichment complete |
| 1 | Fatal error (bad config, DB unreachable, enrichment failed) |

---

## Notes

- Re-running `--once` for the same image or SBOM is safe — SBOM ingest is idempotent, and enrichment results are upserted.
- The `--once` path does not consume from NATS. Start the SBOM ingest (`scanner-worker --once`) first, then enrich (`<name>-worker --once`) if needed. In daemon mode the pipeline triggers automatically.
