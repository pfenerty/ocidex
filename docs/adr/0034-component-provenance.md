---
status: "accepted"
date: 2026-07-11
decision-makers: Patrick Fenerty
---

# Component Provenance Capture & Display

## Context and Problem Statement

Syft-generated CycloneDX SBOMs carry rich per-component provenance in
`properties` — which container layer a package's evidence came from
(`syft:location:0:layerID`), which cataloger found it (`syft:package:foundBy`),
and, for OS packages, the upstream source package it was built from
(`syft:metadata:source*`, `originPackage`, `sourceRpm`). `copyComponents`
discarded all of this on ingest. Three consumer capabilities want it:

1. **Layer / base-image attribution** — show which layer a component came
   from, and whether it's part of the base image.
2. **Source-package vuln matching** — OSV advisories are frequently filed
   against the upstream source package (e.g. `openssl`) rather than the binary
   package syft reports (e.g. `libssl3`); matching only on the binary purl
   misses these.
3. **Cataloger confidence** — surface when a component was found by a
   lower-confidence cataloger (e.g. binary classification) versus a
   package-manager cataloger.

Two questions: how much of this to persist, and whether to extend ingestion to
SPDX SBOMs (the project's other supported format) at the same time.

## Decision Drivers

- Reuse the existing CycloneDX ingestion path; avoid a parallel extractor for a
  format with no current consumer demand.
- Avoid schema bloat from persisting properties on the chance they're useful
  later.
- Keep vulnerability matching format-neutral — it shouldn't need to know
  whether an SBOM was CycloneDX or SPDX.

## Considered Options

1. **Add an SPDX provenance extractor alongside CycloneDX.**
2. **Generic property-bag column** — persist all `syft:*` properties as JSONB
   on `component`, let consumers query into it.
3. **Capability-driven CycloneDX property extraction into typed columns**
   (chosen) — extract only the properties a shipped capability consumes, into
   named nullable columns.

## Decision Outcome

Chosen: **option 3**, with the vuln-matching layer kept purl-keyed so it stays
agnostic to the ingestion decision.

### Stay on CycloneDX

syft's CycloneDX output already carries every property these three
capabilities need (`extractComponentProvenance`, `internal/service/sbom.go:491`).
Adding SPDX ingestion would mean writing a second extractor against SPDX's
different (and less standardized) place for cataloger/layer metadata, for zero
new capability — SPDX support is a lateral move, not a requirement of this
epic. Deferred until an SPDX-specific SBOM source actually needs one of these
three capabilities.

### Capability-driven field promotion

Migration `db/migrations/00046_component_provenance.sql` adds five nullable
columns to `component`: `layer_id`, `found_by`, `source_package`,
`source_version`, `source_purl` (with partial indexes on the first three).
Every column is backed by a shipped consumer:

| Column | Extracted from | Consumer |
|---|---|---|
| `layer_id` | `syft:location:0:layerID` | layer chip, `fromBaseImage` heuristic |
| `found_by` | `syft:package:foundBy` | confidence pill |
| `source_package` / `source_version` | ecosystem-specific (`syft:metadata:source*` for deb, `originPackage` for apk, `sourceRpm` for rpm) | source-package UI indicator |
| `source_purl` | built from the above via `buildSourcePurl` | vuln matching join |

No other `syft:*` properties are persisted. `ComponentDetail`
(`internal/service/search.go:356`) exposes `FoundBy`, `Confidence` (derived,
not stored), `SourcePackage`, `LayerID`, `Layer` (resolved ordinal), and
`FromBaseImage` — each populated only where the underlying capability is
wired up, not as a generic pass-through.

### Vuln layer is purl-keyed, format-neutral

The OSV lookup (`db/queries/vulnerability.sql:167-171`) joins on
`pv.purl = @purl OR (source_purl IS NOT NULL AND pv.purl = source_purl)`, and
computes `matched_via_source` as `NOT bool_or(pv.purl = @purl)` — true only
when a finding matched exclusively via the source purl. This join has no
CycloneDX-specific logic; it would work unchanged against an SPDX-sourced
`source_purl` if that extractor is ever added.

## Consequences

- Good: no speculative schema — every provenance column has a shipped reader.
- Good: vuln matching doesn't need to change if SPDX ingestion is added later.
- Bad — **base-vs-app layer granularity caveat**: `resolveComponentLayer`
  (`internal/service/search_component.go:315`) sets
  `fromBaseImage = hasBase && ordinal == 0` — only layer ordinal 0 is ever
  treated as base image. Two compounding limitations:
  - A multi-layer base image (e.g. `FROM debian AS base` with several `RUN`
    steps) has base content spread across layers 0..N, but only layer 0 is
    flagged. Packages installed in base layers 1..N are under-attributed as
    app-layer.
  - `layer_id` comes from where syft found *evidence* of a package. For
    OS-package-manager ecosystems (deb/apk/rpm), that evidence is the package
    database file (e.g. `/var/lib/dpkg/status`), which only reflects the
    layer of the *last* write to that file — not necessarily the layer where
    a given package's files were actually added. All OS packages installed
    across multiple `RUN apt-get install` layers can end up attributed to a
    single package-DB layer.
  This is accepted as a known limitation, not a bug: fixing it needs
  per-package layer evidence syft doesn't currently emit for OS packages, and
  the current heuristic is directionally correct for the common
  single-`RUN`-install case.

## More Information

- [ADR-0019: Diff Identity Model](0019-diff-identity-model.md) — `source_purl`
  construction reuses the purl-type detection this ADR established.
- Epic: `ocidex-5ur` — Component provenance capture & display. Implementation
  issues: `ocidex-5ur.1` (migration), `.2` (ingest extraction), `.3` (backfill),
  `.4` (OCI layer list), `.5`/`.11`/`.9` (API fields), `.6`/`.10`/`.12` (UI),
  `.7`/`.8` (vuln source-purl matching).

## Key Files

- `db/migrations/00046_component_provenance.sql` — schema
- `internal/service/sbom.go` — `extractComponentProvenance`
- `internal/enrichment/oci/oci.go` — `LayerInfo`, ordered layer persistence
- `internal/service/search_component.go` — `resolveComponentLayer`
- `internal/service/search.go` — `ComponentDetail`
- `db/queries/vulnerability.sql` — source-purl OSV join, `matched_via_source`
