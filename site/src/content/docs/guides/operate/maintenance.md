---
title: Routine maintenance
description: SBOM retention, rotating the encryption key, and backfilling older rows.
sidebar:
  order: 8
---

## SBOM retention

By default OCIDex deletes nothing, and the database grows with every scan. Retention bounds it. Its
settings are `RETENTION_*`, or `api.env.retention.*` in the chart.

**What it deletes:**

- **Registry SBOMs**, once their tag has left the registry's scan window at its last successful
  walk. To keep less from a registry, lower its tags-per-repository setting. Raising it again
  brings the tags back: the next walk scans them.
- **Other SBOMs** (uploads, auto-ingested images, one-off scans) beyond the newest
  `RETENTION_KEEP_LAST` versions (20 by default) of each artifact and flavor in each namespace, and
  optionally anything older than `RETENTION_MAX_AGE`.

**What it never deletes:**

- the newest version of each artifact, and its highest semver version;
- anything running in a registered cluster;
- anything ingested in the last 24 hours, or with an enrichment job still queued or running.

**Turning it on:**

1. Set `RETENTION_MODE=dry-run` (`api.env.retention.mode: dry-run`). Each sweep logs a
   `retention sweep` line with what it would delete, and writes an audit entry. It deletes nothing.
2. When the numbers look right, set it to `on`. The first sweep works through the backlog in
   batches of `RETENTION_BATCH`, and the `ocidex_retention_pruned_total` metric shows its progress.

**Disk space.** Postgres reuses the space deleted rows leave, but doesn't give it back to the file
system. After a large first sweep, reclaim it in a maintenance window with `VACUUM FULL` (which
locks each table while it rewrites it) or online with `pg_repack`.

**Around a sweep.** List pages catch up at the next rollup refresh, within 15 minutes. A deleted
SBOM's page returns 404, and the changelog diffs across the gap.

## Rotating the credential encryption key

Registry credentials and webhook secrets are encrypted with a key from `DATA_ENCRYPTION_KEYS`. Every
key listed there can decrypt; `DATA_ENCRYPTION_ACTIVE_KEY` is the one that encrypts. Each stored
value names the key that sealed it, so rotation happens online:

1. Generate a key: `openssl rand -base64 32`.
2. Add it to `DATA_ENCRYPTION_KEYS` in the Secret, next to the old one (`old:<b64>,new:<b64>`), and
   set `DATA_ENCRYPTION_ACTIVE_KEY=new`.
3. Roll out. New writes use `new`, and everything can still read `old`. The chart's migrate Job
   runs `ocidex migrate encrypt-secrets` on every upgrade, which re-seals every value under `new`.
   Without the chart, run it yourself (`--dry-run` previews it). It's idempotent.
4. Check nothing still uses the old key: a second `encrypt-secrets` run reports `0 rotated`.
5. Remove `old` from `DATA_ENCRYPTION_KEYS` and roll out again.

Removing a key before step 4 makes whatever it sealed unreadable: those registries fail until their
credentials are entered again.

**Turning encryption on for the first time** is the same: set one key and roll out, and
`encrypt-secrets` seals the existing plaintext. Plaintext values keep working until it runs.

**Losing every key** makes the stored credentials unrecoverable, and nothing else. Configure a new
key, re-enter each registry's credentials, and regenerate each webhook secret (and update the
registry that sends it).

## Backfilling older rows

`ocidex migrate backfill` fills in columns that ingest writes today but didn't always write, from
data already in the database: an SBOM's flavor, a component's purl version and its location in the
image, cleaned-up license names and expressions, and the enrichment jobs of SBOMs that were
never enriched. A release's [upgrade notes](/guides/operate/upgrade/#per-version-notes)
say when to run it.

It's idempotent: a second run reports nothing to do. It reads every affected SBOM's stored
document, which takes a while on a large database, so it isn't part of the migrate Job. Run it once,
by hand, with the API image and the chart's Secret:

```sh
kubectl -n <ns> run ocidex-backfill --rm -i --restart=Never \
  --image=ghcr.io/pfenerty/ocidex-api:<version> \
  --overrides='{"spec":{"containers":[{"name":"ocidex-backfill","image":"ghcr.io/pfenerty/ocidex-api:<version>","command":["/ocidex","migrate","backfill"],"envFrom":[{"secretRef":{"name":"<existingSecret>"}}]}]}}'
```

It prints one line per step: `backfill <step>: N updated, N unchanged, N errored`.
