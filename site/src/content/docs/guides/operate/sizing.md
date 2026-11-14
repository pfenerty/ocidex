---
title: Sizing
description: How big OCIDex's database gets, how fast it ingests, and how fast it answers.
sidebar:
  order: 10
---

These numbers come from a measured synthetic corpus, so you can size a new installation from them.

## The corpus

| | |
| --- | --- |
| SBOMs | 10,000 (100 container images × 100 versions) |
| Components | 5,000,000 (500 per SBOM) |
| Dependency edges | 8.5 million |
| Distinct package URLs | 213,000 |

It models shared base images, 5% churn per version and one to three dependencies per library.

## Database size

| Corpus | Database size |
| --- | ---: |
| 5,000 SBOMs, 2.5 million components | 2.6 GB |
| 10,000 SBOMs, 5 million components | 5.2 GB |

Disk grows linearly, at about **1 KB per component**, indexes included. Real SBOMs from syft also
store the original document, so expect more: a real installation scanning public images runs at
about 1.5 MB of database per SBOM in total.

**Give Postgres enough memory to keep the component table and its indexes cached**: about 3 GB at 5
million components. Turn on [retention](/guides/operate/maintenance/#sbom-retention) to keep the
corpus bounded.

## Ingest

One API process ingested 10,000 SBOMs into an empty database in 11 minutes at a concurrency of 8,
about 15 a second. Ingest slows somewhat as the tables grow.

In practice, the per-key rate limit decides a single CI key's speed: `API_RATE_LIMIT_INGEST` is 120
a minute by default. Raise it for a key that loads a large backlog.

Registry scanning isn't covered here: its speed is the scanner's image pull and syft time.

## Read latency

At 10,000 SBOMs, from one API process, every route's 95th-percentile latency was under one second.
The slowest:

| Route | p95 |
| --- | ---: |
| `/api/v1/components/distinct` | 831 ms |
| `/api/v1/licenses` | 377 ms |
| `/api/v1/clusters/{id}/vulns` | 246 ms |
| `/api/v1/vulns/{id}/workloads` | 127 ms |
| `/api/v1/artifacts/{id}/vulns` | 124 ms |
| `/api/v1/components/versions` | 104 ms |
| `/api/v1/artifacts/{id}/changelog` | 54 ms |

Most other routes answered in under 20 ms.

## Background work

- **Rollup refresh**, which keeps the list pages' counts, takes about 85 seconds at 10,000 SBOMs. It
  runs every 15 minutes in the background, on one replica, and never blocks a request.

## Recommendations

- **API replicas** are for availability, not capacity. Two is the chart default.
- **Postgres** needs about 1 KB of disk per component plus the original documents, and enough memory
  to cache the component table.
- **Scanner memory** decides the largest image you can scan. See
  [Scanning and workers](/guides/operate/workers/#the-scanner).
