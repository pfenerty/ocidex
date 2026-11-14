---
title: Back up and restore
description: What to back up, how, and how to restore OCIDex from a backup.
sidebar:
  order: 7
---

## What to back up

| Data | Back up? | Why |
| --- | --- | --- |
| The Postgres database | **Yes** | Everything OCIDex knows: SBOMs, artifacts, users, sessions, API keys, registries, clusters, and scan and enrichment state. |
| `SESSION_SECRET` | **Yes**, separately | Signs session cookies. Restoring with a different one signs everyone out, which is safe but disruptive. |
| `DATA_ENCRYPTION_KEYS` | **Yes**, separately | Decrypts stored registry credentials. Without it, every registry needs its credentials re-entered. Never store it with the database backup: a backup holding both defeats the encryption. |
| OAuth client secrets | **Yes**, separately | Your identity provider can issue new ones, at the cost of an outage. |
| The NATS volume | No | It holds no data of record. Workers claim jobs from Postgres. |
| The vulnerability database volume | No | It's downloaded again at startup. |

Enrichment results are inside the database. Anything lost can be enriched again, since they're
derived from the SBOM and the registry.

## Continuous backup with CloudNativePG

Configure WAL archiving and scheduled base backups on the `Cluster`, to S3 or anything
S3-compatible:

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
  schedule: "0 0 3 * * *"   # CloudNativePG's cron has a seconds field
  backupOwnerReference: self
  cluster: { name: ocidex-pg }
```

CloudNativePG 1.26 and later move object-store backups to the Barman Cloud plugin, with the same
fields on an `ObjectStore` resource. Check backups complete with `kubectl get backups`, and that
WAL archiving is healthy with `kubectl cnpg status ocidex-pg`.

## A nightly dump

Without CloudNativePG, a nightly logical dump is enough for most installations, since OCIDex can
tolerate losing a day of ingests:

```sh
pg_dump "$DATABASE_URL" -Fc --no-owner -f ocidex-$(date +%F).dump
```

## Restore

1. **Stop the writers.** Scale the API and every worker to zero. The operator and the inventory
   agent retry on their own while the API is away.

   ```sh
   kubectl scale deploy -n <ns> -l app.kubernetes.io/part-of=ocidex --replicas=0
   ```

2. **Restore the database.**
   - **CloudNativePG:** create a new `Cluster` with `spec.bootstrap.recovery` pointing at the
     backup, with `recoveryTarget.targetTime` for a point in time. Then point `DATABASE_URL` at its
     `-rw` Service. Restoring into a new cluster leaves the old one to fall back on.
   - **A dump:** restore into an empty database owned by the application role:

     ```sh
     pg_restore -d "$DATABASE_URL" --no-owner --exit-on-error ocidex-YYYY-MM-DD.dump
     ```

3. **Check the schema.** `ocidex migrate status` must list every migration as applied. If the backup
   predates the running version, `ocidex migrate up` (or the chart's migrate Job on the next
   upgrade) brings it forward. Never run an older image against a newer schema.
4. **Restore the secrets.** Use the `SESSION_SECRET` and `DATA_ENCRYPTION_KEYS` the backup was
   taken with.
5. **Start in order.** The API first, until `/ready` answers, then the scanner and enrichers, then
   the vulnerability worker. Jobs that were running when the backup was taken are picked up again
   once their stuck threshold passes.
6. **Check it.** Compare counts with the last values you knew, and sign in:

   ```sql
   SELECT count(*) AS sboms, count(DISTINCT artifact_id) AS artifacts FROM sbom;
   SELECT max(created_at) FROM sbom;   -- the newest ingest the backup holds
   ```

SBOMs ingested after the backup are gone. CI uploads them again on its next build, and registry
polls re-scan their windows.

A restore drill of 200 SBOMs and 40,000 components took one second to dump (5.1 MB) and four
seconds to restore, and every row and API key came back intact.
