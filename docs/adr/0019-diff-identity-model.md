---
status: "accepted"
date: 2026-05-09
decision-makers: Patrick Fenerty
---

# Diff Identity Model: Matching Components Across SBOMs

## Context and Problem Statement

When diffing two SBOMs (`DiffSBOMs`, `DiffSBOMsWithTree`, `GetArtifactChangelog`), every component on each side must be assigned an *identity key* so that "the same package" matches across the two component sets. The diff is the symmetric difference of those keyed sets:

* a key only in the new map → `added`
* a key only in the old map → `removed`
* a key in both with different versions → `modified` (and later classified as `upgraded` / `downgraded`)

Identity is the single most important contract in the diff. Get it wrong and the rest of the system reports phantom changes: a curl that just got a security patch shows up as `removed curl + added curl` instead of an upgrade; a Wolfi package matches an Alpine one because they share a name; a `go-1.24 → go-1.25` rename is reported as two unrelated events.

How should component identity be computed, and which signals are part of identity vs which are version-bearing or noise?

## Decision Drivers

* **Stability across versions.** A package upgrade must not look like remove+add.
* **Distro/repository pinning matters.** `pkg:apk/wolfi/curl` and `pkg:apk/alpine/curl` are not the same package — same name, different provenance, different binaries. They must not match.
* **Heuristics must be local and explainable.** No global state, no fuzzy similarity scores. A reviewer should be able to read two purls and predict the match outcome.
* **Versioned-name packages must collapse.** `go-1.24` removed + `go-1.25` added is one upgrade, not two events. Same for `python-3.12`, `llvm-15`, `nodejs-20`, `gcc-11`.
* **Multi-version installs must not cross-collapse.** If `gcc-11` and `gcc-12` are both installed in the old SBOM and the new SBOM has `gcc-12` and `gcc-13`, the `gcc-11 → gcc-13` collapse is wrong — `gcc-12` survived on its own.
* **Determinism.** Same inputs → same diff, regardless of map iteration order.

## Considered Options

1. **Purl-only identity, all qualifiers preserved.** Identity = entire purl minus the `@version` segment.
2. **Tuple-only identity.** Identity = `(type, group, name)`. Ignore purl.
3. **Layered identity (chosen).** Purl-with-selected-qualifiers when a purl is present; tuple fallback when not. Versioned-name suffix normalization runs as a *post-pass* with an explicit survivor guard.

## Decision Outcome

Chosen: **option 3, layered identity with a post-pass reconcile**.

The identity rules below are normative. They are implemented in `internal/service/changelog.go` (`componentKey`, `stripPurlVersion`, `reconcileVersionedPackages`). Any divergence between the code and this ADR is a bug in one of them.

### Rule 1 — Primary key: purl base + selected qualifiers

If a component has a purl, its identity key is the purl with the version segment removed *and* with qualifier selection applied:

```
pkg:<type>/<namespace>/<name>?<identity-qualifiers>
```

Drop the `@<version>` segment. Then partition the `?key=value&…` qualifier string into two sets:

| Qualifier | Identity? | Rationale |
|---|---|---|
| `distro` | **yes — family only** | Distro **family** is identity (alpine vs wolfi vs chainguard). The trailing version suffix (`-3.14.3`, `-22.04`, `-34`) is normalized away so the same package matches across distro releases. See "Distro normalization" below. |
| `arch` | **yes** | `curl` for `amd64` is not the same artifact as `curl` for `arm64` |
| `epoch` | **yes** | epoch is part of Debian package identity, not just version |
| `repository_url` | **yes** | same name, different repo → different supply chain |
| `vcs_url`, `download_url` | no | provenance-of-record but not identity-bearing; a mirror change should not break the diff |
| `checksum`, `tag`, `commit` | no | content-identifying; varies per build |
| anything else | no (default) | unknown qualifiers are treated as noise |

The retained qualifiers are sorted alphabetically before being appended, so two purls that differ only in qualifier order produce identical keys.

**Distro normalization.** The `distro=` qualifier value commonly carries
both family and release (`alpine-3.14.3`, `fedora-34`, `debian-12`,
`ubuntu-22.04`). Treating the whole value as identity-bearing causes a
phantom remove+add for every package whenever the underlying distro
release bumps — even though the identity (alpine) is unchanged. The
qualifier value is normalized by stripping a trailing `-<version>`
suffix matching `-[0-9][A-Za-z0-9.-]*$`. So:

| Raw distro value | Identity-form |
|---|---|
| `alpine-3.14.3` | `alpine` |
| `alpine-3.15.0` | `alpine` |
| `fedora-34` | `fedora` |
| `debian-12` | `debian` |
| `ubuntu-22.04` | `ubuntu` |
| `wolfi-os` | `wolfi-os` (no numeric suffix; unchanged) |
| `chainguard` | `chainguard` (no suffix; unchanged) |

Family separation is preserved by purl namespace
(`pkg:apk/alpine/...` vs `pkg:apk/wolfi/...`), so the normalization
does not collapse cross-family identities.

**Examples.**

| Old purl | New purl | Same identity? |
|---|---|---|
| `pkg:deb/ubuntu/curl@7.81.0-1?arch=amd64` | `pkg:deb/ubuntu/curl@7.81.0-2?arch=amd64` | yes — modified |
| `pkg:apk/wolfi/curl@8.6.0` | `pkg:apk/alpine/curl@8.6.0` | **no** — different namespaces |
| `pkg:apk/wolfi/curl@8.6.0?distro=wolfi-os` | `pkg:apk/wolfi/curl@8.7.0?distro=wolfi-os` | yes |
| `pkg:apk/wolfi/curl?download_url=https://a.example` | `pkg:apk/wolfi/curl?download_url=https://b.example` | yes (download_url is not identity) |
| `pkg:apk/alpine/curl?distro=alpine-3.14.3` | `pkg:apk/alpine/curl?distro=alpine-3.15.0` | yes — distro version stripped, both normalize to `distro=alpine` |
| `pkg:apk/alpine/curl?distro=alpine-3.15.0` | `pkg:apk/wolfi/curl?distro=wolfi-os` | **no** — purl namespace differs (alpine vs wolfi) |

### Rule 2 — Fallback key: type + group + name

When a component has no purl (which happens for some non-OS components and for tools that emit incomplete CycloneDX), identity is the tuple `(type, group, name)` joined with NUL bytes (today's behavior). Group is empty when absent. This is a coarser key, and components that fall through to it are matched only by name and ecosystem.

### Rule 3 — Versioned-name post-pass with survivor guard

After the symmetric-difference pass produces an initial change list, a second pass collapses pairs whose names share a base and differ only in a numeric version suffix.

The normalization rule strips a trailing version suffix matching the regex `-[0-9][0-9.]*$` from the package name (or from the last path segment of the purl-base, when a purl is present). Two changes form a collapse candidate when:

1. one is `removed` and the other is `added`,
2. they share the same normalized base, *and*
3. **(survivor guard)** no other component in the new map has the same normalized base — i.e., the old "version-named slot" was not split into multiple slots.

Only collapse-eligible pairs are merged into a single `modified` entry; everything else stays as separate `added`/`removed` events. The survivor guard prevents the false collapse described in the third decision driver: with `{gcc-11, gcc-12}` → `{gcc-12, gcc-13}`, the survivor `gcc-12` exists on both sides under the regular identity rules, and the remaining single removed (`gcc-11`) does not collapse against the single added (`gcc-13`) because there are *two* normalized-`gcc` entries on the new side.

The survivor guard is symmetric: the collapse also fails when the *old* map has multiple entries sharing the normalized base. This protects against a multi-version install shrinking to one.

### Rule 4 — Determinism

Identity-bearing qualifiers are emitted in alphabetical order. The change list is sorted by `(type, group, name)` after both passes. The post-pass iterates a deterministic ordering of candidate keys. None of the rules depend on map iteration order in their output.

### Consequences

* Good: distro-pinned packages stop pseudo-matching across alpine/wolfi/chainguard family lines.
* Good: the versioned-name reconcile is no longer fooled by multi-version installs.
* Good: the qualifier partition is data, not code — adding a new identity-bearing qualifier is a one-line change.
* Good: the rules are local and testable in isolation, without spinning up a full diff.
* Neutral: existing diffs may shift slightly when re-run because previously-conflated packages will now show as separate entries. This is a one-time correction, not regression.
* Bad: components without purls remain identified by `(type, name, group)`, which is a weaker key. We accept this — the upstream fix is to ensure ingest writes a purl whenever possible, not to invent a stronger fallback.
* Bad: the qualifier allowlist requires maintenance as new purl spec qualifiers emerge. The mitigation is that unknown qualifiers default to *noise* (not identity), so an unfamiliar new qualifier produces stable matches by default rather than splitting them.

### Confirmation

Confirmed by the golden-file tests in `bqh.27` (E3), which assert match outcomes for:

* `go-1.24` / `go-1.25` collapse → one `modified` upgrade.
* `gcc-11` + `gcc-12` (old) vs `gcc-12` + `gcc-13` (new) → `gcc-12` is unchanged (regular match), `gcc-11` removed, `gcc-13` added — *no* collapse.
* `pkg:apk/wolfi/curl` vs `pkg:apk/alpine/curl` → distinct identities, two events.
* `pkg:deb/ubuntu/curl?arch=amd64` vs `pkg:deb/ubuntu/curl?arch=arm64` → distinct identities.
* `pkg:apk/wolfi/curl?download_url=A` vs `pkg:apk/wolfi/curl?download_url=B` → matched (download_url is noise).
* `?arch=amd64&distro=wolfi-os` vs `?distro=wolfi-os&arch=amd64` → matched (qualifier order normalized).

The same fixtures are used by `bqh.25` (E1, survivor-guard implementation) and `bqh.26` (E2, qualifier-policy implementation).

## Pros and Cons of the Options

### Option 1 — Purl-only identity, all qualifiers preserved

* Good: the strongest possible identity; no false matches.
* Bad: every qualifier becomes load-bearing, including provenance-of-record fields like `download_url` that *will* change between mirrors and rebuilds. Diffs would be flooded with phantom remove+add pairs.
* Bad: components without purls have no identity at all.

### Option 2 — Tuple-only identity

* Good: simplest possible model; `(type, group, name)` is always available.
* Bad: collapses distro-pinned packages across alpine/wolfi/chainguard. A `curl` upgrade in one distro and a different `curl` removal from another distro look like a single upgrade.
* Bad: throws away the precision purl gives us when the SBOM tooling actually emits good purls (Syft, apko, Wolfi-native tools).

### Option 3 — Layered identity (chosen)

* Good: uses purl precision when available, gracefully degrades when not.
* Good: qualifier policy is explicit and reviewable in this ADR — the partition is data.
* Good: the survivor guard makes the versioned-name reconcile safe in the multi-install case.
* Bad: two-pass algorithm (initial diff + reconcile) is slightly more complex than a single-pass keyed match.
* Bad: identity-qualifier allowlist needs maintenance as the purl spec evolves.

## More Information

* Implementation lives in `internal/service/changelog.go`. Today's `componentKey` / `stripPurlVersion` / `reconcileVersionedPackages` cover Rules 1–3 partially; the qualifier policy (Rule 1) and survivor guard (Rule 3) are tracked as `ocidex-bqh.26` and `ocidex-bqh.25` respectively.
* Related: [ADR-0020 — Image flavor detection from SBOM contents](0020-image-flavor-axis.md) (uses the same `?distro` qualifier signal at a higher level).
* Related: [ADR-0021 — Backend-computed diff tree and rollups](0021-backend-computed-diff-tree.md) (depends on stable identity to attach `nodeRef` cross-references).
* Epic: `ocidex-bqh` — Diff & tree display: backend-computed, flavor-aware.
* Spec reference: [purl spec](https://github.com/package-url/purl-spec) — qualifier semantics.
