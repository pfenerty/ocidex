# Sizing

How big OCIDex's Postgres gets and how fast its read routes answer, for a measured corpus
(ocidex-xxee.5). Use it to size a new install, and repeat the run to check a change against
the budget.

## Corpus

| | |
|---|---|
| SBOMs | 10,000 (100 container artifacts × 100 versions) |
| Components | 5,000,000 (500 per SBOM) |
| Dependency edges | 8,486,300 |
| Distinct purls | 213,379 |
| Vulnerability findings | 4,320 purls (2%) mapped to synthetic advisories |
| Licenses | 6, one per component |
| Clusters | 1, with 40 running workloads |

The corpus is `cmd/loadgen -seed 1 -artifacts 100 -versions 100 -components 500`, ingested
through the API. Its shape (shared base images, 5% churn per version, 1–3 dependencies per
library) is described in [DEVELOPMENT.md § Synthetic corpus](DEVELOPMENT.md#synthetic-corpus).
The vulnerability findings were inserted directly, because no vuln-worker ran. That gives the
vulnerability routes the same row counts a real match would.

## Postgres

| Corpus | Database size | `component` | `dependency` | `component_license` | `sbom` |
|---|---:|---:|---:|---:|---:|
| 5,000 SBOMs, 2.5M components | 2.6 GB | | | | |
| 10,000 SBOMs, 5M components | 5.2 GB | 2.7 GB | 1.5 GB | 625 MB | 180 MB |

Disk grows linearly, at about **515 KB per SBOM of 500 components**, so about 1 KB per
component, indexes included. loadgen's documents are small, so this is mostly the parsed
rows. Real Syft documents add their `raw_bom` on top: ocidex-dev, with real images, runs at
about 1.5 MB of database per SBOM in total.

Measured on Postgres 18.6 at its defaults (`shared_buffers` 128MB). The working set of the
measured routes fit in the OS page cache of a 16 GB machine.

**Background work that grows with the corpus:**
* **Rollup refresh** (every 15 minutes, and after ingests): **85.5s** at 10k SBOMs. It runs on
  the API's background pool, behind an advisory lock, so it never blocks a request.
* **Retention queries** (ADR-0056): about 130 ms each on ocidex-dev at 4.2k SBOMs, dominated by
  the semver parse over every version.

## Ingest throughput

One API process, `API_RATE_LIMIT_INGEST=0`:

| SBOMs ingested | Concurrency | Time | Rate |
|---|---:|---:|---:|
| First 5,000 (into an empty database) | 1 | 7m15s | 11.5/s |
| First 5,000 (into an empty database) | 8 | 6m23s | 13.1/s |
| 10,000 (into an empty database) | 1 | 29m48s | 5.6/s overall |

Ingest slows as the tables grow: the second 5,000 took about three times as long as the
first. Two limits apply in practice:
* **Rate limit.** The default per-key ingest limit (`API_RATE_LIMIT_INGEST`, 120 a minute, so
  2 a second) is far below what the API sustains, so it decides the rate for a single CI key.
* **Concurrency.** Parallel ingest streams barely help (13.1/s at 8 against 11.5/s at 1): the
  work is in Postgres, not the API. Concurrent ingests used to deadlock on the license upsert;
  that's fixed (ocidex-5prp).

Registry scanning isn't measured here: its throughput is the scanner worker's image pull and
Syft time, which this corpus doesn't exercise.

## Read latency

Every GET route in [AUTH_MATRIX.md](AUTH_MATRIX.md), 20 timed samples each after one warm-up,
sequential, from the same machine, with an admin key. The budget is the server's
`slowRequestThreshold`, **5s**. Slowest p95 first:

| Route | p50 | p95 | max | status |
|---|---:|---:|---:|---|
| `/api/v1/licenses/{id}/components` | 7.56s | 9.64s | 10.51s | 200 |
| `/api/v1/components/distinct` | 788ms | 831ms | 1.41s | 200 |
| `/api/v1/licenses` | 302ms | 377ms | 382ms | 200 |
| `/api/v1/clusters/{id}/vulns` | 242ms | 246ms | 247ms | 200 |
| `/api/v1/vulns/{id}/workloads` | 119ms | 127ms | 150ms | 200 |
| `/api/v1/artifacts/{id}/vulns` | 113ms | 124ms | 126ms | 200 |
| `/api/v1/components/versions` | 98ms | 104ms | 104ms | 200 |
| `/api/v1/artifacts/{id}/changelog` | 49ms | 54ms | 57ms | 200 |
| `/api/v1/sboms/{id}` | 6ms | 35ms | 56ms | 200 |
| `/api/v1/sboms/{id}/components` | 10ms | 27ms | 41ms | 200 |
| `/api/v1/licenses/lookup` | 24ms | 26ms | 26ms | 200 |
| `/api/v1/clusters/{id}/images` | 20ms | 22ms | 32ms | 200 |
| `/api/v1/clusters/{id}/workloads` | 20ms | 21ms | 21ms | 200 |
| `/api/v1/enrichment-jobs` | 20ms | 21ms | 22ms | 200 |
| `/api/v1/vulns` | 11ms | 19ms | 23ms | 200 |
| `/api/v1/components/purl-types` | 14ms | 16ms | 16ms | 200 |
| `/api/v1/components` | 11ms | 13ms | 14ms | 200 |
| `/api/v1/users/me/vulns` | 11ms | 11ms | 11ms | 200 |
| `/api/v1/registries` | 0ms | 10ms | 50ms | 200 |
| `/api/v1/sboms/{id}/vulns` | 9ms | 10ms | 10ms | 200 |
| `/api/v1/sboms/{id}/dependencies` | 7ms | 10ms | 11ms | 200 |
| `/api/v1/registries/trust-summary` | 1ms | 9ms | 12ms | 200 |
| `/api/v1/sboms/diff-tree` | 6ms | 7ms | 7ms | 200 |
| `/api/v1/namespaces/by-name/{name}` | 0ms | 6ms | 8ms | 200 |
| `/api/v1/sboms/lookup` | 4ms | 5ms | 6ms | 200 |
| `/api/v1/enrichment-jobs/summary` | 4ms | 4ms | 4ms | 200 |
| `/api/v1/sboms/diff` | 3ms | 4ms | 5ms | 200 |
| `/api/v1/` | 0ms | 4ms | 7ms | 200 |
| `/api/v1/artifacts/{id}/contains` | 3ms | 3ms | 3ms | 200 |
| `/api/v1/artifacts/{id}/vuln-summary` | 2ms | 3ms | 3ms | 200 |
| `/api/v1/vulns/{id}` | 0ms | 2ms | 2ms | 200 |
| `/api/v1/artifacts/{id}/license-summary` | 1ms | 2ms | 2ms | 200 |
| `/api/v1/artifacts/lookup` | 1ms | 1ms | 3ms | 200 |
| `/api/v1/artifacts/{id}/versions` | 1ms | 1ms | 1ms | 200 |
| `/api/v1/artifacts/{id}/usages` | 1ms | 1ms | 1ms | 200 |
| `/api/v1/artifacts` | 0ms | 1ms | 1ms | 200 |
| `/api/v1/registries/{id}/preview` | 0ms | 1ms | 2ms | 502 (20 errors) |
| `/api/v1/components/{id}` | 0ms | 1ms | 1ms | 200 |
| `/api/v1/namespaces/{id}/members` | 0ms | 1ms | 2ms | 200 |
| `/api/v1/users/me/activity` | 0ms | 0ms | 1ms | 200 |
| `/api/v1/artifacts/{id}/sboms` | 0ms | 0ms | 1ms | 200 |
| `/api/v1/users/me/artifacts` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/registries/drift-feed` | 0ms | 0ms | 3ms | 200 |
| `/api/v1/users/me/watches/feed` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/clusters/{id}/unknown-images` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/jobs/{id}` | 0ms | 0ms | 1ms | 404 (20 errors) |
| `/api/v1/artifacts/{id}` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/namespaces` | 0ms | 0ms | 7ms | 200 |
| `/api/v1/admin/status` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/components/{id}/vulns` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/clusters/{id}/k8s-namespaces` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/registries/by-name/{name}` | 0ms | 0ms | 1ms | 200 |
| `/api/v1/users` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/users/me/sources` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/sboms` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/sources` | 0ms | 0ms | 8ms | 200 |
| `/api/v1/sboms/{id}/drift` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/auth/identities` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/namespaces/{id}` | 0ms | 0ms | 11ms | 200 |
| `/api/v1/registries/{id}` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/users/me/clusters` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/users/me/watches` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/users/me/drift-feed` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/auth/keys` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/users/me/namespaces` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/users/me/registries` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/clusters/{id}` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/sources/{id}` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/jobs` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/clusters` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/auth/providers` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/users/me` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/discover` | 0ms | 0ms | 0ms | 200 |
| `/ready` | 0ms | 0ms | 0ms | 200 |
| `/api/v1/stats` | 0ms | 0ms | 0ms | 200 |
| `/health` | 0ms | 0ms | 0ms | 200 |

`/registries/{id}/preview` returns 502 because the measured registry's host doesn't exist,
and `/jobs/{id}` returns 404 because the corpus has no scan jobs. Their timings are only the
error path.

**Over budget:** `/licenses/{id}/components`, p95 9.6s: ocidex-zbe5. Its cost grows with how
many components carry the license, not with the page size. Every other route's p95 is under
1s.

The server's `http_server_request_duration_seconds` agrees: that route's mean over the run was
8.7s.

## Recommendations

* **Postgres:** budget about 1 KB of disk per stored component (515 KB per 500-component
  SBOM), plus `raw_bom`. Turn on [retention](OPERATIONS.md#sbom-retention) to keep the corpus
  bounded. Give the database enough RAM to keep `component` and its indexes cached: at 5M
  components that's about 3 GB.
* **API replicas:** one API process answered every route but one in under 1s at 10k SBOMs, so
  replicas are for availability, not capacity. The rollup refresh and the retention sweep each
  run on one replica at a time, whatever the count.
* **Ingest:** a single CI key is limited by `API_RATE_LIMIT_INGEST`. Raise it for a key that
  ingests a large backlog.

## Reproducing

```bash
# 1. Run the API against an empty, migrated database with the rate limits off
#    (API_RATE_LIMIT_INGEST=0, API_RATE_LIMIT_HEAVY=0), and create an upload source
#    and an API key with the ingest capability.

# 2. Load the corpus.
go run ./cmd/loadgen -url http://localhost:8080 -api-key "$KEY" -source <source-id> \
  -seed 1 -artifacts 100 -versions 100 -components 500 -concurrency 1

# 3. Time every route. routes.txt holds "<route> <path>" lines with real ids filled in.
go run ./cmd/loadgen measure -url http://localhost:8080 -api-key "$KEY" \
  -routes routes.txt -samples 20 > results.md
```
