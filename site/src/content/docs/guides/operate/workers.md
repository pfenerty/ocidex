---
title: Scanning and workers
description: Configure and scale the scanner, the enrichers and the vulnerability worker.
sidebar:
  order: 4
---

Everything slow runs in a worker, never in the API. Each worker claims jobs from a table in
Postgres; NATS only wakes it up sooner. If NATS is down, workers fall back to polling the database
every 30 seconds, and nothing is lost.

## The scanner

`scanner-worker` pulls each selected image, generates its SBOM with syft and ingests it. The API
decides *what* to scan (registry polls, webhooks, cluster inventory, the Scan button) and the
scanner does the work.

| Setting | Chart value | Notes |
| --- | --- | --- |
| `SCANNER_ENABLED` | `api.env.scannerEnabled` | Lets the API queue scans. On by default in the chart. |
| `REGISTRY_POLLER_ENABLED` | `api.env.registryPollerEnabled` | Polls registries whose scan mode is `poll` or `both`. Leader-elected across API replicas. |
| `SCANNER_MAX_CONCURRENCY` | `scannerWorker.env.maxConcurrency` | Scans per pod at once. Each holds an image in memory. The chart default is 1. |
| `SCANNER_MAX_IMAGE_BYTES` | `scannerWorker.env.maxImageBytes` | Images larger than this, in compressed layer bytes, fail from their manifest without being pulled. 2 GiB by default. |
| Memory limit | `scannerWorker.resources.limits.memory` | 4 GiB by default. |

**Size the memory limit and the image ceiling together.** syft holds the whole unpacked file list
in memory. An image too big for the limit doesn't fail cleanly: the container is OOMKilled, along
with any other scan sharing the pod, and the job is retried until it runs out of attempts. The
ceiling exists so an image that would do that is refused before it's pulled. To scan bigger
images, raise both.

The scanner also needs temporary disk to unpack layers: `scannerWorker.tmpSizeLimit`, 8 GiB by
default, holds an image of about 1 GB compressed.

### Scan modes

Each registry has a scan mode:

| Mode | What triggers a scan |
| --- | --- |
| `poll` | The API lists tags every poll interval and queues new digests. Needs `REGISTRY_POLLER_ENABLED`. |
| `webhook` | The registry calls `/api/v1/registries/{id}/webhook` on each push. |
| `both` | Either. |

Docker Hub and GHCR can't send webhooks to OCIDex, so they always poll.

## The enrichers

Each enricher runs as its own Deployment, listed in `enricherWorkers`: `oci-metadata-worker`,
`git-worker`, `user-enricher-worker` and `provenance-worker`. They share the sizing and settings in
`enricherWorkerDefaults`, and an entry can override either for itself.

The provenance enricher does the most work per job (it pulls signature layers and runs a cosign
verification), so the chart gives it more memory and a concurrency of 2. The other three use
a few tens of MiB.

| Setting | Chart value | Notes |
| --- | --- | --- |
| `ENRICHMENT_MAX_CONCURRENCY` | `enricherWorkerDefaults.env.maxConcurrency` | Jobs per pod at once, 10 by default. |
| `ENRICHMENT_MAX_ATTEMPTS` | | Attempts before a job is left failed for the **Jobs** page's Retry button. |
| `PROVENANCE_TIMEOUT`, `PROVENANCE_MAX_LAYER_BYTES` | | Bound one provenance check's time and memory. Raise the limit and the memory together. |
| `GIT_MAX_RESPONSE_BYTES` | | Largest GitHub response the git enricher reads. |

## The vulnerability worker

`vuln-worker` downloads the grype vulnerability database, matches new SBOMs within about a minute,
and matches everything again after each database update. It talks only to Postgres and the
database download site.

- The database is about 3 GB, and an update needs room for the download plus two copies. The chart
  gives it a 10 GiB PersistentVolumeClaim (`vulnWorker.db.persistence`). Use node-local storage, not
  NFS: the database is SQLite.
- It runs one replica with the Recreate strategy, because the volume is ReadWriteOnce.
- Give it memory for the page cache. Its own heap is about 150 MiB, but matching slows sharply
  when the database's pages are squeezed out. The chart's 2 GiB limit holds it at about two
  seconds per SBOM.
- `vulnWorker.db.updateURL` points it at a mirror, for an installation without internet access.

## Scaling

Replicas are for availability more than capacity. One API process answers almost every route in
well under a second at 10,000 SBOMs; see [Sizing](/guides/operate/sizing/).

To scale workers on queue depth, turn on KEDA (`keda.enabled: true`). The chart then creates a
ScaledObject per worker, scaling the scanner between `keda.scanner.minReplicas` and `maxReplicas`,
and each enricher between `keda.enrichment.minReplicas` and `maxReplicas`. KEDA owns the replica
count from then on, so `scannerWorker.replicas` is ignored.

## One-shot jobs

`scanner-worker` and every enricher worker also run as a one-shot job: `--once` processes a single
item and exits, 0 on success and 1 on failure. Use it from a Kubernetes Job, a CI task or by hand.

**Scan one image:**

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: scan-myapp
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: scanner
          image: ghcr.io/pfenerty/ocidex-scanner-worker:<version>
          args: ["--once"]
          env:
            - name: SCAN_IMAGE
              value: ghcr.io/acme/myapp:1.4.2
          envFrom:
            - secretRef:
                name: ocidex-secrets
```

| Variable | |
| --- | --- |
| `SCAN_IMAGE` | **Required.** The image: `registry/repo:tag` or `registry/repo@sha256:…`. |
| `SCAN_REGISTRY_ID` | The registry to attribute the SBOM to. |
| `SCAN_AUTH_USERNAME`, `SCAN_AUTH_TOKEN` | Registry credentials. |
| `SCAN_INSECURE` | `true` for a plain-http registry. |

**Enrich one SBOM** with one enricher: run that worker's image with `--once` and
`ENRICH_SBOM_ID=<sbom id>`. It runs only that enricher, and doesn't trigger the enrichers that
depend on it, so run each one you need in turn.

Both are safe to repeat: ingest skips an SBOM it already has, and enrichment results overwrite the
previous ones.
