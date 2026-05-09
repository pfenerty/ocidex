---
status: "accepted"
date: 2026-05-09
decision-makers: Patrick Fenerty
---

# Image Flavor Detection from SBOM Contents

## Context and Problem Statement

OCIDex builds a per-artifact changelog by ordering SBOMs along a timeline and diffing consecutive entries. Today the timeline is grouped by `(subjectVersion, architecture)` — see `changelogGroupKey` in `internal/service/changelog.go`. This works as long as every SBOM for an artifact is built against the same base distribution.

It breaks when an artifact ships variants. A common pattern is:

* `myapp:1.2.3-alpine` (alpine-3.19, apk packages)
* `myapp:1.2.3-debian` (debian-bookworm, deb packages)
* `myapp:1.2.3-distroless` (no OS packages)

All three carry the same `subjectVersion` (`1.2.3-...`) but the *contents* differ wildly. Worse, `compareVersionStrings` splits the version on `-` and `.` and orders `1.2.3-alpine` before `1.2.3-debian` purely on suffix lexicography. The timeline interleaves across base distros, and consecutive entries are diffs *between distros*, not between releases. Every package looks like it was added or removed.

The fix is to add a **flavor** axis to the changelog grouping, alongside architecture. Two questions to answer:

1. Where does flavor come from?
2. What schema does it use?

## Decision Drivers

* **No required user action.** Must work on existing SBOMs without re-tagging or re-ingesting with extra params. The system already has thousands of SBOMs; backfill must be possible.
* **SBOM tooling diversity.** Syft, Trivy, apko, hand-written CycloneDX — each emits different metadata. The detector must degrade gracefully, never reject.
* **Apk-family disambiguation.** Alpine, Wolfi, and Chainguard all use `pkg:apk/...` purls. Diffing across these families is meaningless; they must produce distinct flavors.
* **Distroless / scratch support.** Images with no OS package manager are a legitimate flavor, not an edge case.
* **Tag suffix conventions are not universal.** `1.2.3-alpine`, `alpine-1.2.3`, `1.2.3` (with flavor implicit) — every codebase does it differently. Tags are a hint, not a contract.
* **Determinism and stability.** Re-ingesting the same SBOM must yield the same flavor. The detector is not a model.

## Considered Options

1. **Tag-suffix parsing.** Strip a known suffix set (`-alpine`, `-bookworm`, `-slim`, `-distroless`, …) from `subjectVersion`. Per-artifact override pattern for non-conforming tags.
2. **SBOM-content layered detection (chosen).** Detect at ingest from the SBOM body itself, with a layered priority (OS metadata → purl fingerprint → tag suffix as last resort). Persist on `sbom.flavor`.
3. **Manual per-artifact configuration.** User declares the flavor for each ingest call, or sets a per-artifact mapping table.

## Decision Outcome

Chosen: **option 2, layered SBOM-content detection**, with the tag-suffix heuristic retained as the final fallback inside the same detector. Manual override is deferred — if and when it's needed, it can be added as an `IngestParams.Flavor` field that wins over detection.

The detector runs at ingest time and writes to `sbom.flavor` (text, indexed). It never returns an error: if every layer fails, the result is the literal string `unknown` and the UI surfaces a single un-flavored bucket. This is implemented in `bqh.29` (F2); migration is `bqh.28` (F1); backfill is `bqh.30` (F3).

### Layer 1 — OS metadata properties (primary)

CycloneDX SBOMs from Syft and recent Trivy versions carry OS information either as:

* properties on `metadata.component` or top-level `metadata.properties` with names like:
  * `syft:image:os:name` (e.g., `alpine`, `debian`, `ubuntu`, `wolfi`)
  * `syft:image:os:version-id` (e.g., `3.19`, `12`, `20240315`)
  * `syft:distro:id` / `syft:distro:version-id` (older Syft)
  * Trivy emits similar fields under `aquasecurity:trivy:` namespaces.
* CycloneDX 1.5+ structured `metadata.component.properties` for OS info (less common in the wild today; will become primary as tooling catches up).

When `os:name` is present, the flavor is `<os_name>-<os_version_id>` (lowercased, version optional). The version is dropped only when the property is absent — never inferred.

This layer is checked first because it is the most precise: it distinguishes `alpine-3.18` from `alpine-3.19` and `debian-bookworm` from `debian-bullseye`, which the purl layer cannot.

### Layer 2 — Purl-type fingerprint (secondary)

When OS metadata is absent or insufficient, count purl types across all non-file components and take the dominant ecosystem:

| Dominant purl type | Disambiguator | Flavor |
|---|---|---|
| `apk` | `?distro=wolfi*` qualifier present on majority | `wolfi` |
| `apk` | `?distro=chainguard*` qualifier present | `chainguard` |
| `apk` | otherwise | `alpine` (no version) |
| `deb` | namespace contains `ubuntu` | `ubuntu` |
| `deb` | otherwise | `debian` |
| `rpm` | namespace contains `fedora` | `fedora` |
| `rpm` | namespace contains `rhel` / `redhat` / `centos` | `rhel` |
| `rpm` | otherwise | `rpm-other` |
| no OS-pm purls, only language ecosystems (`golang`, `npm`, `pypi`, `gem`, …) | — | `distroless` |
| empty component list | — | `scratch` |

"Dominant" means strict majority of OS-package-manager purls. A 50/50 split (extremely unusual) falls through to layer 3.

The `?distro=` qualifier check is what disambiguates apk-family flavors. Syft emits `distro=wolfi-os`, `distro=alpine-3.19`, etc. on apk purls. When present and consistent across the majority of apk purls, it wins over the bare-namespace heuristic.

### Layer 3 — Tag suffix heuristic (last resort)

When neither metadata nor purl fingerprint resolves, fall back to parsing `subjectVersion` for a known suffix set. The suffix list is hardcoded in the detector:

```
-alpine -alpine3 -wolfi -chainguard
-debian -debian-slim -bookworm -bullseye -bookworm-slim -bullseye-slim
-ubuntu -jammy -noble -focal
-distroless -scratch -slim
-rhel -ubi -ubi-minimal -ubi-micro -fedora
```

Match is anchored to end-of-string, longest-suffix wins. The matched suffix (without the leading `-`) is the flavor; the rest of the version remains as `subjectVersion`. If no suffix matches, the flavor is `unknown`.

This layer is intentionally weak — it exists so that genuinely tag-only-distinguished SBOMs aren't lost, not as a primary signal.

### Schema

Flavor is a single lowercase string. Two shapes are valid:

* `<family>` — e.g., `alpine`, `debian`, `wolfi`, `distroless`, `scratch`, `unknown`.
* `<family>-<version_id>` — e.g., `alpine-3.19`, `debian-bookworm`, `ubuntu-24.04`.

The version segment is included only when layer 1 supplied it. The grouping logic in `bqh.31` (F4) treats `alpine-3.18` and `alpine-3.19` as distinct flavor groups, so a major distro upgrade *will* break the timeline — which is the correct behavior, since the package set changes wholesale.

When a SBOM has no detectable flavor, the literal `unknown` is stored. This is a deliberate sentinel, not a NULL — it makes flavor a non-nullable axis in the changelog grouping and avoids special-casing in the join.

### Consequences

* Good: changelog grouping becomes correct for multi-flavor artifacts without any user-side change.
* Good: distroless and scratch images are first-class flavors, not edge cases.
* Good: layered design means a regression in any single tool (e.g., Syft drops a property name) causes graceful degradation, not a hard failure.
* Good: the detector is pure — same SBOM bytes always produce the same flavor — so backfill and re-ingest are deterministic.
* Neutral: `flavor` becomes part of the SBOM contract surfaced to the UI; if we later refine the detector, existing rows need re-detection (a goose-style data migration). We accept this; flavor strings are simple enough to remap with a SQL update.
* Bad: distinguishing `alpine-3.18` from `alpine-3.19` will split timelines that some users may have considered the same artifact line. We treat this as correct, but the UI must make the flavor switcher discoverable so users can pivot back to a unified view.
* Bad: tooling that emits neither OS metadata nor `?distro` qualifiers (older Trivy, certain hand-written generators) will fall through to tag-suffix parsing — strictly weaker. The mitigation is a CLAUDE.md note on which generators we support well, plus the option to add `IngestParams.Flavor` later.

### Confirmation

Confirmed by the `bqh.34` (F7) test suite, which covers:

* alpine 3.18 vs alpine 3.19 distinguished via `os:version-id`.
* wolfi vs alpine via `?distro=wolfi-os` qualifier on apk purls.
* chainguard vs wolfi via `?distro=chainguard*` qualifier.
* debian-bookworm vs debian-bullseye via `os:version-id`.
* distroless detection from purls-without-OS-pm (only `pkg:golang/...`).
* scratch detection from empty component list.
* tag-suffix fallback when both metadata and purls are missing.
* `unknown` when nothing resolves.
* changelog grouping: a multi-flavor artifact produces one timeline per `(arch, flavor)` pair.

## Pros and Cons of the Options

### Option 1 — Tag-suffix parsing only

* Good: trivially simple to implement.
* Good: matches the user's mental model of "I tagged it `-alpine` so it should know."
* Bad: breaks immediately for artifacts that don't follow the convention.
* Bad: cannot tell `1.2.3-alpine-3.18` from `1.2.3-alpine-3.19` unless the tag carries the version explicitly, which is rare.
* Bad: silently misclassifies images whose tags lie (e.g., a `:latest` tag on what is actually an alpine image).

### Option 2 — SBOM-content layered detection (chosen)

* Good: signal is intrinsic to the artifact, not a string convention.
* Good: graceful degradation across tooling — every SBOM gets *some* flavor classification.
* Good: works for existing data via deterministic backfill.
* Good: distinguishes apk-family members (alpine vs wolfi vs chainguard) via `?distro` qualifiers.
* Bad: detector logic is data-driven and accumulates rules over time; tests are mandatory.
* Bad: distroless/scratch detection is heuristic (absence of OS-pm purls) rather than positive evidence.

### Option 3 — Manual per-artifact configuration

* Good: maximum precision — no inference at all.
* Good: works for arbitrarily weird taxonomies the detector wouldn't catch.
* Bad: requires the user to declare a mapping for every artifact before ingest is meaningful.
* Bad: every wrong/missing config produces broken changelogs; high-touch maintenance.
* Bad: backfill is impossible without a human in the loop.

## More Information

* Implementation issues: `bqh.28` (F1, migration), `bqh.29` (F2, detector), `bqh.30` (F3, backfill), `bqh.31` (F4, grouping), `bqh.32` (F5, API), `bqh.33` (F6, UI), `bqh.34` (F7, tests).
* Identity-bearing qualifier policy is shared with [ADR-0019 — Diff identity model](0019-diff-identity-model.md): the same `?distro` qualifier that distinguishes apk family members at the package level distinguishes flavors at the SBOM level.
* Backend-computed contract: [ADR-0021 — Backend-computed diff tree and rollups](0021-backend-computed-diff-tree.md).
* Epic: `ocidex-bqh` — Diff & tree display: backend-computed, flavor-aware.
* References: [Syft properties](https://github.com/anchore/syft/blob/main/syft/format/cyclonedxhelpers/format.go), [purl spec qualifiers](https://github.com/package-url/purl-spec).
