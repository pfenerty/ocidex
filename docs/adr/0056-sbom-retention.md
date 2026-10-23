---
status: "accepted"
date: 2026-10-23
decision-makers: Patrick Fenerty
---

# SBOM retention: registry SBOMs follow their window, everything else keeps the newest N versions

## Context and Problem Statement

Nothing deletes an SBOM except an explicit `DELETE`. Every scan adds a full SBOM, and its
components, dependencies, hashes, licenses, enrichment and vulnerability matches go with it, so
the database grows without bound. On ocidex-dev an SBOM averages about 1.5k components, and the
corpus reached about 36k SBOMs and 52 GB before homelab-23k pruned it by hand to about 3.9k
SBOMs and 5.8 GB.

[ADR-0053](0053-registry-scan-scope.md) bounds what a registry walk *scans*, and leaves removing
what is already stored to retention (its rule S6). SBOMs that don't come from a registry walk
have no bound at all. CI uploads are about a third of ocidex-dev (1,501 of 4,208), and the
inventory agent's auto-ingest adds more.

Deleting is the easy part. Every table that hangs off `sbom` cascades, and `scan_jobs.sbom_id`
is set to null. The hard parts are deciding what may go, and making sure it doesn't come back:

* The walker re-queues any in-window digest that has no SBOM (ADR-0053 S6).
* Changelog and diff (ADRs [0019](0019-diff-identity-model.md)–[0021](0021-backend-computed-diff-tree.md))
  compare versions, so history is the product.
* Images that are running must stay answerable.

What should retention delete, what must it never delete, and how does it run?

## Decision Drivers

* **Off by default.** Deleting data is never a surprise. An operator turns it on, and can see
  what it would do before it does it.
* **A deleted SBOM stays deleted**, unless the user widens the scope on purpose.
* **Every protected class is testable.** The rules are written so each one is a WHERE clause
  and an integration test (ocidex-xxee.2).
* **Running images are always answerable**, whatever the policy says.
* **Changelog keeps its latest entry.** Each artifact's newest change stays visible.
* **One mechanism per source.** The registry window is already a per-repository count. A
  second count on top of it would fight the walker.
* **A sweep must not hurt the API.** Bulk deletes cascade into the largest tables.

## Considered Options

* Two classes split by source: registry SBOMs leave when their tag leaves the window, and other
  SBOMs keep the newest N versions per series
* One keep-newest-N rule for every SBOM, with a tombstone for registry prunes
* An age limit only
* Per-namespace policies

## Decision Outcome

Chosen option: "Two classes split by source". It is the only option where the registry's
`tag_limit` and retention can't disagree. ADR-0053 already makes the window the count limit for
registry SBOMs, so retention reuses it instead of adding a second number the walker would undo.
Everything else gets the simple count-and-age rule it lacks today.

### Rule R1: series and versions

A **series** is `(namespace_id, artifact_id, flavor)`. Namespaces are separate tenants
(ADR-046), so one namespace's SBOMs never count toward another's. `flavor` is the changelog axis
from ADR-0020. It is never null; `unknown` is a flavor.

A **version** is one `subject_version` within a series. Retention keeps or prunes whole
versions. A kept version keeps every SBOM it has: each platform of a multi-arch image and each
rescan. An SBOM with a null `subject_version` is a version on its own.

Versions are ordered by **ingest time**: the newest `created_at` among the version's SBOMs. Ingest
time, not semver, because uploads and auto-ingest have no reliable version scheme. A semver
series is still covered by P1.

### Rule R2: class W, out of window (registry SBOMs)

An SBOM is a **registry SBOM** when its source is `oci_registry` and a `scan_jobs` row links it
to a registry (`registry_id`). It is pruned when **all** of these hold:

1. The registry's most recent **successful** walk covered the SBOM's repository. A failed or
   partial walk never prunes. A repository that has left the filter (removed from
   `repositories`, or no longer matching the patterns) isn't covered, so its SBOMs are left
   alone.
2. That walk did not select the SBOM's digest. "Selected" means the walk's window (ADR-0053 S1)
   resolved to it, matched on `coalesce(sbom.index_digest, sbom.digest)` so every platform of
   a selected index stays.
3. No protected class (R4) applies.

This needs the window to be stored. Each successful walk records its selected
`(repository, tag, digest)` set per registry, replacing the previous walk's set. The poller,
the ad-hoc walk and the preview already call one selection function (S1), so the walk writes
the set from there.

There is no tombstone (ADR-0053 S6). Raising `tag_limit` brings the tags back into the window,
and the next walk scans them again.

### Rule R3: class N, newest N versions (all other SBOMs)

Every SBOM that isn't a registry SBOM is in class N: uploads, auto-ingested running images,
and direct scans. Within each series, a version is pruned when **either**:

* it is not among the newest `keep_last` versions, or
* `max_age` is set and the version's ingest time is older than it.

No protected class (R4) may apply in either case.

`keep_last` has a floor of 2, so an artifact always keeps its newest changelog entry. Registry
SBOMs are never in class N: the walker would re-queue any in-window version this class deleted,
and the registry's `tag_limit` already counts them.

Class N writes no tombstone. Nothing re-ingests an upload, and an auto-ingested image that runs
again is meant to be scanned again.

### Rule R4: the protected set

These SBOMs are never pruned, by either class:

* **P1, newest.** Every SBOM of the newest version in its series (R1 order). In a series where
  any `subject_version` parses as semver (ADR-0053's `semverRe`), the highest semver version is
  protected as well, so a late backport can't push out the current release.
* **P2, running.** Any SBOM whose `digest` or `index_digest` equals a
  `cluster_workload.image_digest`, in any cluster of any namespace. This includes clusters whose
  agent has stopped reporting: `cluster_workload` keeps its last snapshot (ADR-044 K7), and
  retention errs on the side of keeping.
* **P3, in flight.** Any SBOM ingested within the last 24 hours, or with an `enrichment_jobs`
  row in `queued` or `running`. A cascade must not delete a row a worker is processing, and a
  fresh SBOM may still be getting vulnerability matches and enrichment.

These are deliberately **not** protected:

* **Watched artifacts.** `artifact_watch` is per artifact, not per SBOM. P1 and the floor of 2
  keep the newest version and the entry before it, which is all the watch feed shows.
* **Derived relationships** (ADR-041, ADR-048). They are computed when read. When an old image
  version is pruned, it drops out of `/usages` and `/contains`, and that is correct.
* **Provenance drift events.** They cascade with their SBOM. An event about a version nobody
  keeps isn't worth keeping the version for.

### Rule R5: configuration is installation-wide

| Setting | Default | Meaning |
|---|---|---|
| `RETENTION_MODE` | `off` | `off`, `dry-run` or `on`. `dry-run` computes and reports candidates and deletes nothing. |
| `RETENTION_KEEP_LAST` | `20` | Class N: versions kept per series. 0 turns class N off. Otherwise at least 2. |
| `RETENTION_MAX_AGE` | unset | Class N: optional age cut-off, as a Go duration (`2160h` is 90 days). |
| `RETENTION_REGISTRY_WINDOW` | `true` | Class W on or off. |
| `RETENTION_INTERVAL` | `6h` | Gap between sweeps. |
| `RETENTION_BATCH` | `50` | SBOMs deleted per transaction. |

There are no per-namespace overrides. ADR-0053 ruled out per-namespace quotas, and a
per-namespace policy would let a namespace admin delete history an installation admin wants
kept. Registries already get per-registry scope through `tag_limit`. A per-namespace class N
override can be added later without changing these rules.

### Rule R6: execution

* **One sweeper.** The sweep is leader-elected with a Postgres advisory lock
  (`ocidex-retention`), the way the rollup refresher and the poller are, and runs in the
  process that hosts them (ocidex-xxee.3).
* **Batches.** The candidate query (ocidex-xxee.2) returns at most `RETENTION_BATCH` SBOM ids
  for one class. Each batch is one transaction that deletes those `sbom` rows and lets the
  cascades run. The sweep pauses between batches and stops at the end of its pass or on
  shutdown. Batches stay small because each SBOM cascades into about 1.5k component rows and
  their children. homelab-23k measured about 4 minutes per 500 SBOMs.
* **Candidates are checked again at delete time.** The delete statement repeats the
  protected-set conditions, so an image that started running, or an SBOM that picked up an
  enrichment job, after selection is skipped.
* **Reporting, not events.** A sweep writes one audit record and one log line with counts per
  class. It doesn't publish `sbom.deleted` per SBOM, which would flood the audit log and the
  NATS relay with thousands of entries. Metrics: `ocidex_retention_pruned_total{class}` and the
  sweep duration.
* **Derived tables catch up.**
  * Rollups are rebuilt on the refresher's normal cycle, within 15 minutes.
  * Vulnerability rows lose their mappings by cascade, and the vulnerability refresher prunes
    orphans at the end of its next pass (ocidex-cecc.1).
* **Disk.** Postgres reuses freed space but doesn't return it to the filesystem. Getting it
  back needs `VACUUM FULL` or `pg_repack`, and OPERATIONS.md documents that.

### Rule R7: changelog and diff across a gap

Pruned versions disappear. There's no tombstone row in `sbom`, and the changelog diffs the
versions on either side of a gap as consecutive entries. A diff or link naming a pruned SBOM id
returns 404, and that includes ids in old audit records. This matches the window: an
out-of-window tag is already absent from history.

### Consequences

* Good, because nothing is deleted until an operator sets `RETENTION_MODE`, and `dry-run`
  shows the counts per class first.
* Good, because registry SBOMs have one limit. Lowering `tag_limit` shrinks the stored history
  at the next sweep, and raising it brings tags back.
* Good, because uploads and auto-ingest, the sources with no bound today, get one.
* Good, because each protected class is one predicate with one test.
* Bad, because the walk must store its selected window, which is a new table and a write on
  every successful walk.
* Bad, because changelog entries can span a gap without saying so. A follow-up could record
  pruned versions per series and show "N versions pruned" between entries.
* Bad, because `RETENTION_KEEP_LAST` is one number for every series in the installation. A
  series built on every commit and one released twice a year get the same N.
* Bad, because a cluster whose agent is gone for good keeps its images protected (P2) until
  the cluster is deleted.
* Bad, because disk isn't returned without a `VACUUM FULL` or `pg_repack`.

### Confirmation

* Integration tests (ocidex-xxee.2), one per rule, against Postgres:
  * **Class N:** a series with `keep_last + 3` versions prunes exactly the 3 oldest, and the
    cascades leave no orphan rows.
  * **Class W:** a registry SBOM outside the last successful walk's window is pruned. The same
    SBOM is kept after a failed walk, and kept when its repository has left the filter.
  * **Multi-arch:** every platform SBOM of an index the window selected is kept.
  * **P1:** the newest version, and the highest semver version when a later backport exists,
    survive `keep_last` 2.
  * **P2:** an SBOM whose `index_digest` matches a running workload in another namespace
    survives.
  * **P3:** an SBOM under 24 hours old, and one with a queued enrichment job, survive.
  * **Delete-time check:** a candidate that becomes protected between selection and delete is
    skipped.
  * **Floor:** `keep_last` 1 is rejected at config load.
* A test with two sweepers on one database shows only one sweeps (ocidex-xxee.3).
* `dry-run` deletes nothing and reports the same counts that `on` then deletes.

## Pros and Cons of the Options

### Two classes split by source

* Good, because the registry window stays the single count for registry SBOMs, as ADR-0053
  intends.
* Good, because no tombstones are needed. Neither class has a source that would re-ingest what
  it deletes.
* Bad, because an operator has two mechanisms to understand. The `dry-run` report names the
  class of each count.

### One keep-newest-N rule for every SBOM, with a tombstone for registry prunes

* Good, because there is one rule to explain.
* Bad, because it fights the walker. With `tag_limit` 50 and N 20, retention deletes 30
  in-window SBOMs, the next walk re-queues them, and the next sweep deletes them again.
* Bad, because the only way to stop that loop is a tombstone per deleted tag, which leaves 30
  tags permanently in the window but skipped. That stores exactly what `tag_limit` 20 would,
  with more machinery, and raising `tag_limit` no longer brings anything back without a
  `force` walk. For registry SBOMs, `tag_limit` is already the retention count.

### An age limit only

* Good, because "90 days" is easy to explain.
* Bad, because it is unbounded for a series built on every commit, the case that grows
  fastest.
* Kept as the optional `RETENTION_MAX_AGE` within class N.

### Per-namespace policies

* Good, because namespaces with different needs can differ.
* Bad, because it lets a namespace admin delete what the installation admin wants kept, and
  ADR-0053 already ruled out per-namespace quotas.
* Deferred. R5 leaves room to add a class N override per namespace.

## More Information

* Implementation:
  * **ocidex-xxee.2:** candidate query and service. This now includes storing the walk's
    selected window.
  * **ocidex-xxee.3:** the leader-elected sweep, its config, metrics and chart values.
* Related:
  * [ADR-0053](0053-registry-scan-scope.md): rules S1 and S6.
  * [ADR-044](0044-k8s-inventory-agent.md): `cluster_workload` and auto-ingest.
  * [ADR-0020](0020-image-flavor-axis.md): flavor.
  * [ADR-049](0049-vulnerability-matching-via-grype.md): vulnerability store pruning.
  * homelab-23k: the manual prune that shaped R6's batch size.
