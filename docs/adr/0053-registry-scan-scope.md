---
status: "proposed"
date: 2026-10-20
decision-makers: Patrick Fenerty
---

# Registry scan scope: filter, order, keep the newest N tags per repository

## Context and Problem Statement

Adding a registry scans its whole tag history. `tag_patterns` (globs, or the `semver` keyword)
decide *which* tags count, but nothing decides *how many*. Adding `registry.k8s.io` with
`kube-apiserver` and `semver` queued about 4.1k SBOMs, and ocidex-dev grew to about 36k SBOMs and
50 GB.

Deleting the excess does not stick. `walkRepo` (`internal/scanner/catalog.go`) skips a digest only
while an SBOM for it exists (`FetchKnownDigests`). Once an SBOM is deleted, its digest is unknown
again, and the next poll submits it. `InsertScanJob` then resets the old `succeeded` row to
`queued`.

A self-hosted user should be able to add a registry in one step and have the defaults keep the
corpus bounded. Prisma Cloud's registry scan keeps the N most recently modified images per
repository. Harbor tag retention has per-repository "most recent N" and "pushed within N days"
rules. Flux ImagePolicy separates a filter step from an order step. Anchore has no count limit,
only an account-wide ceiling.

How should a registry bound what it scans, and how does that bound survive deletes?

## Decision Drivers

* A new registry must be safe by default. The user should not need to understand tag schemes
  before the first poll.
* The bound must hold over time. A deleted SBOM must not come back on the next poll.
* History is the product. Changelog and diff (ADRs 0019–0021) compare versions, so the default
  keeps enough of them.
* Polling should not get more expensive, and the common configurations should get cheaper.
* The user must be able to see what a configuration will scan before saving it.
* Images running in a cluster are always worth knowing about, whatever the registry config says.

## Considered Options

* Per-repository selection window: filter, then order, then keep the newest N tags
* A per-registry SBOM quota
* An age limit only
* No mechanism; document tighter `tag_patterns`

## Decision Outcome

Chosen option: "Per-repository selection window". It is the only option that keeps a single
repository bounded, needs no cross-repository fairness rule, and costs nothing extra for semver
and lexical tags. Prisma Cloud and Harbor both scope their count to each repository for the same
reason.

### Rule S1: one selection function, three steps

Each registry gains three settings:

| Setting | Type | Default | Meaning |
|---|---|---|---|
| `tag_limit` | integer ≥ 0 | 50 | Keep the newest N tags per repository. 0 means unlimited. |
| `tag_order` | `semver` \| `created` \| `lexical` \| null | null (auto) | How "newest" is decided. |
| `max_tag_age_days` | integer ≥ 1 \| null | null | Drop tags whose image is older than this. Valid only when the effective order is `created`. |

For each repository the walker applies, in order:

1. **Filter.** `repositories`, `repository_patterns` and `tag_patterns` work as they do today.
   Attached-artifact tags (`IsAttachedArtifactTag`, the cosign `sha256-….sig/.att/.sbom` scheme)
   are removed here, so they never take a slot in the window.
2. **Order.** Sort the remaining tags newest first, using the effective order (S2).
3. **Keep.** If `max_tag_age_days` is set, drop tags older than the cutoff. Then keep the first
   `tag_limit` tags.

The selected tags then go through `scanTag` exactly as today: HEAD the manifest, skip known
digests, expand indexes, submit. The poller, the ad-hoc `ScanRegistry` walk (with or without
`force`) and the preview (S7) all call the same function. A `force` walk re-queues digests
inside the window; it does not widen the window.

The window is computed **before** the known-digest skip. Tags that already have SBOMs still take
their slots. Otherwise every walk would skip the tags it has already ingested and pull the next N
from further back in history, and the window would walk backwards through the repository until
the whole history was ingested.

A selected tag that turns out to be unscannable (an unsupported or attestation manifest, found
only after the HEAD) yields no SBOM. The next tag does not move up to take its place. The window
is a set of tags, and it must not depend on what the registry returns for each one.

### Rule S2: ordering semantics

**Effective order.** An explicit `tag_order` wins. When it is null, the order is `semver` if
`tag_patterns` contains the `semver` keyword, and `created` otherwise.

**Tie-break, all orders.** Tags that compare equal are ordered by raw tag string, byte-wise
descending. Tag names are unique within a repository, so the result is a total order, and the
same input always selects the same window.

**`semver`.** A tag is parseable when it matches the existing `semverRe`
(`^v?(\d+)\.(\d+)\.(\d+)(-[A-Za-z0-9.]+)?(\+[A-Za-z0-9.]+)?$`), the same expression the
`semver` pattern matches with. Parseable tags compare by SemVer 2.0.0 precedence (§11):

* A leading `v` is ignored. `v1.9.3` and `1.9.3` have equal precedence, and the tie-break puts
  `v1.9.3` first.
* Major, minor and patch compare as integers, so `1.10.0` is newer than `1.9.3`. Leading zeros,
  which `semverRe` accepts (`01.2.3`), are read as integers too.
* A prerelease has lower precedence than its release: `1.9.3-rc.2` is older than `1.9.3` and
  newer than `1.9.2`. Prerelease identifiers compare left to right. Numeric identifiers compare
  as integers (`rc.10` is newer than `rc.2`), alphanumeric ones byte-wise (`beta` is newer than
  `alpha`), a numeric identifier is older than an alphanumeric one, and a shorter set of
  identifiers is older when it is a prefix of the longer (`alpha` is older than `alpha.1`).
* Build metadata (`+…`) is ignored for precedence. `1.0.0+b.2` and `1.0.0+b.1` tie, and the
  tie-break puts `+b.2` first.
* Prereleases are not filtered out. They take window slots like releases.
* Tags that `semverRe` does not parse can still reach the order step when `tag_patterns`
  combines `semver` with globs (`["semver", "latest"]`). They sort after every parseable tag,
  ordered among themselves by the tie-break. With more than `tag_limit` semver tags, such a tag
  is outside the window. The preview shows this before the registry is saved.

Worked example, newest first: `v1.10.0`, `v1.9.3`, `1.9.3`, `v1.9.3-rc.10`, `v1.9.3-rc.2`,
`v1.9.3-beta`, `v1.9.3-alpha.1`, `v1.9.3-alpha`, `v1.9.2`, then unparseable `stable`, `latest`.

**`lexical`.** Tags compare as raw strings, byte-wise; the greatest string is the newest. This
suits date-stamped tags (`20261020`, `2026.10.20-1`). It does not suit unpadded numbers (`9` is
newer than `10`).

**`created`.** Tags compare by their image's build date: the config blob's `created`, falling
back to the `org.opencontainers.image.created` annotation and then the config labels (the
precedence `ociGetImageMetadata` already applies). Parsing is RFC 3339. For an image index, the
date is the index's `org.opencontainers.image.created` annotation, falling back to the date of
the first platform manifest `ociExpandIndex` returns (it already skips the attestation entries,
whose OS is empty or `unknown`). A tag whose date is missing or unparseable sorts after every dated tag, and is
dropped when `max_tag_age_days` is set, since it cannot be shown to be within the cutoff.

Reproducible builds often set `created` to the Unix epoch or to `SOURCE_DATE_EPOCH`. apko,
ko and melange do. Under `created` those images all sort as the oldest and fall to the
tie-break. Registries of such images should use `semver` or `lexical`, and the preview makes that
visible.

### Rule S3: the limit counts tags, not digests or SBOMs

`tag_limit` counts tags. Several tags that resolve to one digest each take a slot, and that
digest is scanned once (the existing `scannedDigests` de-duplication). Multi-arch expansion
happens after selection, so 50 tags of a four-platform index queue up to 200 SBOMs. The preview
reports the SBOM estimate as well as the tag count.

### Rule S4: untagged manifests use their own window, ordered by `created`

With `include_untagged`, the discoverer's untagged manifests (`DiscoveredManifest.Tag == ""`) get
a separate window of `tag_limit` entries, ordered by `created` with `max_tag_age_days` applied.
`tag_order` does not apply, because untagged manifests have no names to compare. Discovered
manifests that do carry a tag are skipped in this pass. They belong to the tag window, and
submitting them here would let tags from outside the window back in.

### Rule S5: existing registries get 50 too

The migration adds `tag_limit integer not null default 50`, `tag_order text` (null) and
`max_tag_age_days integer` (null) to `registry`, so every existing registry gets the default. That
stops future backfill on installs like ocidex-dev at once. SBOMs already ingested outside the new
window are not deleted by the migration. Removing them is retention's job (S6). The `OCIRegistry`
CRD gains `tagLimit` (schema default 50), `tagOrder` and `maxTagAgeDays`, and the operator writes
them through like the existing fields.

### Rule S6: a pruned SBOM stays pruned

Two kinds of removal, and both have to hold:

* **Out of window.** The walker submits only selected tags, so an SBOM whose tag has left the
  window is never re-queued. Retention (ocidex-xxee.1) gets a prune class for these: "registry
  SBOM whose tag is no longer in its registry's window". The class's protected set is retention's
  decision. At minimum it protects images running in a cluster (ADR-044) and the newest SBOM per
  repository. No tombstone is written for these prunes. If the user later raises `tag_limit`, the
  tags come back into the window and are scanned again, which is what raising the limit is for.
* **Explicit delete of an in-window SBOM.** The tag is still selected, so the walker would submit
  it again. Deleting a registry-sourced SBOM therefore sets its `scan_jobs` row (keyed by
  `registry_id@digest`) to a new state, `pruned`. The `InsertScanJob` upsert leaves a `pruned`
  row unchanged, as it already does for a `failed` one. A `force` walk resets `pruned` rows inside
  the window to `queued`. The migration adds `pruned` to the `scan_jobs.state` check constraint.

### Rule S7: preview before saving

`POST /registries/preview` (an unsaved config) and `GET /registries/{id}/preview` run S1 without
submitting anything. Per repository they return the matched, selected, skipped-by-limit and
skipped-by-age counts, plus an estimate of the SBOMs a walk would queue. The estimate takes the
platform count from the first selected tag and multiplies it out. The CLI gets
`ocidex registry preview`, and the operator writes the summary into the `OCIRegistry` status. A
`created`-order preview does the same metadata requests a walk does, so it is not free on large
repositories.

### Rule S8: webhooks and running images

* **Webhook push.** A pushed tag must match the filter, as today. Under `semver` or `lexical`, it
  must also fall within the window, which costs one tag list for the repository. Under `created`,
  a pushed tag passes. A push is almost always the newest build, and the next walk's view of the
  window is the one retention acts on.
* **Running images.** Cluster auto-ingest (ADR-044 K9, and K10 once ocidex-ve0f.1 accepts it)
  never consults the window. A running image is scanned whatever its tag's position.
* **Direct scans** of a named image reference are not registry walks and are not affected.

### Consequences

* Good, because a new registry is bounded by default. `kube-apiserver` with `semver` queues 50
  tags (times its platforms) instead of about 4.1k SBOMs.
* Good, because polling gets cheaper under `semver` and `lexical`. The walk HEADs only the
  selected tags, where today it HEADs every matching tag on every poll.
* Good, because deletes stick. A pruned SBOM is either outside the window or tombstoned.
* Good, because the window is deterministic. The same tag list always selects the same tags,
  which the tests and the preview rely on.
* Bad, because `created` order needs each candidate's build date. The first walk of a large
  repository fetches the manifest and config for every matching tag. A digest's date never
  changes, so a digest→created cache can live across walks, and later walks pay one HEAD per tag,
  the same as today.
* Bad, because 50 is still a lot for some deployments. A demo install such as ocidex-dev should
  set about 5–10 per upstream repository and check the total with the preview (homelab-23k).
* Bad, because prereleases take window slots. A project that cuts many release candidates
  crowds out older releases. Excluding them needs a glob or a future keyword (see More
  Information).
* Bad, because existing installs keep their out-of-window SBOMs until retention ships and runs.

### Confirmation

* Unit tests for the selection function cover the S2 worked example, `v` prefix ties, build
  metadata ties, leading zeros, unparseable tags mixed with semver, `lexical`, `created` with
  equal and missing dates, `max_tag_age_days` with a missing date, `tag_limit` 0, and the S4
  untagged window, including a tagged manifest from the discoverer being skipped.
* `catalog_test.go`: a fake registry with 200 semver tags and `tag_limit` 10 queues 10 tags (times
  their platforms). After those SBOMs are deleted out of band, a second walk queues nothing
  outside the window. After an explicit delete through the API, a second walk does not re-queue
  the tombstoned digest, and a `force` walk does.
* A migration test shows existing `registry` rows come out with `tag_limit` 50, and that
  `scan_jobs` accepts `pruned`.
* An API test shows preview returns counts and creates no `scan_jobs` rows.
* Validation rejects `max_tag_age_days` when the effective order is not `created`, and a negative
  `tag_limit`, in the API, the CLI and the CRD schema.

## Pros and Cons of the Options

### Per-repository selection window

* Good, because it maps onto how registries are organized. Each repository is one product's
  release history.
* Good, because it composes with the existing filters instead of replacing them.
* Neutral, because it moves the size question to choosing N, which the preview makes concrete.
* Bad, because it adds three fields across the database, API, CLI, CRD and web form.

### A per-registry SBOM quota

* Good, because one number bounds the whole registry.
* Bad, because what to drop at the cap needs a cross-repository rule, and any such rule lets one
  busy repository starve the rest.
* Bad, because the cap is in SBOMs, which the walker only knows after HEADs and index expansion.
* Out of scope by the maintainer's decision: no hard per-registry or per-namespace quotas.

### An age limit only

* Good, because "the last 90 days" is easy to explain.
* Bad, because it is unbounded for a repository that builds on every commit.
* Bad, because it needs every tag's build date, which costs requests and does not work for
  reproducible builds dated to the epoch.
* Kept as the optional `max_tag_age_days` on top of the count.

### No mechanism; document tighter `tag_patterns`

* Good, because there is nothing to build.
* Bad, because globs choose by name and cannot express "the newest N".
* Bad, because it leaves the delete-and-re-queue loop in place.

## More Information

* **Why 50 and not Prisma Cloud's 5.** Prisma scans for vulnerabilities, where only recent
  images matter. OCIDex is a self-hosted catalog whose changelog and diff views compare versions,
  so the default keeps a useful history. A demo or a small install lowers it per registry.
* **Possible follow-up:** a `semver-release` keyword for `tag_patterns` that matches only tags
  without a prerelease. It is cheap to add if prereleases crowding the window turns out to matter.
* Implementation: ocidex-gxlr (migration, selection function, walk), ocidex-5y0r.2 (preview),
  ocidex-5y0r.3 (form presets), ocidex-5y0r.4 (walk stats and metrics), ocidex-xxee.1 (the
  retention prune class). The migration is `00081`, since `00080` is taken.
* Related: [ADR-044](0044-k8s-inventory-agent.md) (running images, K9),
  [ADR-0019](0019-diff-identity-model.md)–[0021](0021-backend-computed-diff-tree.md) (changelog and diff).
