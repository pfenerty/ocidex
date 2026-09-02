---
status: "accepted"
date: 2026-09-02
decision-makers: Patrick Fenerty
---

# Command artifacts resolve to main-module components by binary path

## Context and Problem Statement

ADR-041 derives artifact relationships by matching an image SBOM's components against tracked
artifacts, keyed on ADR-019's identity key. For every ocidex-built binary that match fails, and
both `/usages` and `/contains` return `[]`.

The two sides describe the same binary in different vocabularies:

| | type | name | group | purl base |
|---|---|---|---|---|
| Application artifact (declared by CI) | `application` | `enrichment-worker` | `github.com/pfenerty/ocidex` | `pkg:golang/github.com/pfenerty/ocidex/cmd/enrichment-worker` |
| Component in the image's SBOM (emitted by Syft) | `library` | `github.com/pfenerty/ocidex` | — | `pkg:golang/github.com/pfenerty/ocidex` |

Neither ADR-041 R1 layer reaches across that. The purl bases differ, and the tuple branch is
unreachable because both rows carry a purl.

The mismatch is not a mistake on either side. A `golang` purl names a *module*; Syft's
`go-module-binary-cataloger` reads `runtime/debug.BuildInfo` and emits exactly one component for
`Main`, the module. But one Go module produces many independently shipped commands — this repo
ships twelve — and every one of them is `pkg:golang/github.com/pfenerty/ocidex` in a scanner's
eyes. `push-sboms.nu` invented the `/cmd/<name>` suffix precisely so the twelve stay distinct
artifacts, and its comment says so.

So the question is not "which side is wrong". It is: **what, in the SBOM, says which command an
image actually ships?**

## Decision Drivers

* One image ships one binary. Any rule that makes `ghcr.io/pfenerty/ocidex-git-worker` report
  that it contains all twelve application artifacts is worse than the empty list it replaces —
  ADR-041 R3 rejected a rule for exactly that reason.
* The match must stay derived. ADR-041's non-goals rule out a stored `artifact_link` table and
  CI-declared links, and nothing here is the "relationship that component data cannot express"
  that would reopen either.
* Identity must not fork. ADR-041 R1 requires relationship code to call `componentKey`, not
  reimplement it; anything added here has to sit beside that call rather than replace it.
* Whatever disambiguates has to be present in SBOMs already ingested, or the fix does not apply
  to the corpus that motivated it.

## Considered Options

* Declare the module purl on the application artifact, so both sides agree
* Prefix rule alone: treat `pkg:golang/<module>/cmd/<x>` as matching `pkg:golang/<module>`
* Prefix rule plus binary-path disambiguation
* Leave it unmatched and say so in the UI

## Decision Outcome

Chosen option: **prefix rule plus binary-path disambiguation**, because it is the only option that
produces the relationship the reader is asking for without also producing eleven false ones.

The first two options fail identically. Both make the twelve application artifacts
indistinguishable to the matcher — one by giving them the same purl base, the other by making
`pkg:golang/github.com/pfenerty/ocidex` match all twelve `/cmd/<x>` suffixes. Every ocidex image
would then claim to contain every ocidex binary. That is a wrong answer, not an approximate one.

The information that separates them is already in the SBOM and was simply not being kept. Syft
records the file each component was read from:

```json
{"name": "syft:location:0:path", "value": "/git-worker"}
```

`syft:location:0:layerID` — the sibling key in the same location record — has been persisted since
migration `00046`, so this is a field the ingest path already walks past.

### Rule R6 — Command match

Extending ADR-041's rules. A component matches an artifact, *in addition to* R1, when all four
hold:

1. Both purls are of type `golang`. The rule is scoped to the ecosystem whose identity model
   creates the problem; nothing else is affected by it.
2. The component's purl base is a proper prefix of the artifact's purl base **at a path
   boundary** — `pkg:golang/github.com/pfenerty/ocidex` against
   `pkg:golang/github.com/pfenerty/ocidex/cmd/enrichment-worker`, never a bare string prefix that
   would pair `.../ocidex` with `.../ocidex-cli`.
3. The component records a file path.
4. The basename of that path equals the artifact's name.

Condition 4 is the whole rule; 1–3 are its guards. `--subject-name` in `push-sboms.nu` is the
binary's filename, which is what the image's `syft:location` path ends in, so the two agree by
construction rather than by coincidence.

R6 is additive: a pair that satisfies R1 matches on R1, unchanged. R6 is consulted only for pairs
R1 rejects.

### Rule R7 — No path, no match

A component with no recorded file path does not match under R6, ever. Not "matches everything with
the right module", not "matches when unambiguous".

This is a fail-closed rule and it is deliberate. SBOMs ingested before `component.file_path`
existed have NULL there, and so does anything produced by a tool that does not emit locations.
Treating NULL as a wildcard would turn precisely the corpus this ADR exists to fix into the
twelve-false-edges outcome the decision rejects. The backfill below is what moves an existing SBOM
from "no match" to "matched", and until it runs the behaviour is the status quo.

### Persistence

`component.file_path TEXT`, nullable, from `syft:location:0:path`, populated in
`extractComponentProvenance` alongside the layer and cataloger fields it already reads.

Existing rows are backfilled by `cmd/backfill-provenance`, which already decodes `raw_bom` and
matches components back by bom-ref. No new backfill mechanism, and no new migration-time data
rewrite: the column ships empty and fills in when the command is run.

### Consequences

* Good, because the relationship is still derived, still shares `componentKey` with diff, and
  still needs no link table.
* Good, because the disambiguator is the SBOM's own evidence — the file the scanner read — rather
  than a convention agreed between our CI and our matcher.
* Good, because `component.file_path` is useful beyond this: "which binary in this image carries
  this package" is a question the component provenance view could not previously answer.
* Bad, because the rule is ecosystem-specific. `pkg:golang` is named in the matcher. Accepted:
  the problem is specific to an ecosystem where one module yields many shipped commands, and a
  rule that pretended otherwise would be generality without a second case to justify it.
* Bad, because a relationship appears only after the backfill has run over an SBOM. R7 makes that
  visible as "no relationship yet" rather than as a wrong one.
* Neutral: drift (ADR-041 R2) compares the component's *module* version against the application
  artifact's `subject_version`. Today those come from different producers and use different
  schemes — an image records `v0.0.2` while `push-sboms.nu` sends `0.0.0-<sha>` — so a command
  relation will usually report drift. The comparison is doing what R2 says; it is the two version
  schemes that disagree, and reconciling them is a CI change, not a matching change.

### Confirmation

Integration tests covering:

* a command artifact matching the image whose SBOM carries its binary (R6);
* the other commands of the same module **not** matching that image — the false-positive case
  the decision turns on;
* a component with NULL `file_path` matching nothing under R6 (R7);
* a bare string prefix (`.../ocidex` vs `.../ocidex-cli`) not matching, proving the path-boundary
  guard (R6.2);
* R1 matches continuing to resolve unchanged.

## Pros and Cons of the Options

### Declare the module purl on the application artifact

* Good, because the declared purl would then be a real Go module purl, which `/cmd/<x>` is not.
* Bad, because all twelve artifacts collapse to one purl base and every image matches all of them.
* Bad, because it needs a producer change plus a backfill of `artifact.purl`, and still leaves the
  matcher unable to tell the twelve apart.

### Prefix rule alone

* Good, because it is a few lines of SQL and no schema change.
* Bad, because it is the same collapse arrived at from the other direction.

### Prefix rule plus binary-path disambiguation

* Good, because it is exact: one image, one binary, one artifact.
* Bad, because it costs a column, an ingest change, and a backfill.

### Leave it unmatched

* Good, because it is honest and free.
* Bad, because the relationship *is* recoverable from data already ingested, which makes "we
  cannot tell" untrue.

## More Information

* Extends [ADR-0041 — Derived artifact relationships](0041-derived-artifact-relationships.md);
  R1–R5 are unchanged and R6/R7 continue that numbering.
* Identity layering: [ADR-0019 — Diff identity model](0019-diff-identity-model.md).
* Declared identity for uploaded artifacts:
  [ADR-0040 — Non-container artifact identity](0040-non-container-artifact-identity.md).
* Producer side: `.tektonic/jobs/sbom-push/push-sboms.nu`.
* Issue: `ocidex-7gf7.11`.

### Non-goals

* **Recording the Go main *package* path.** `runtime/debug.BuildInfo.Path` holds
  `github.com/pfenerty/ocidex/cmd/git-worker` and would identify the command directly, but Syft
  does not emit it, and inferring it would mean parsing binaries ourselves. Reopen if a scanner
  starts emitting it.
* **Generalizing R6 beyond `pkg:golang`.** Reopen when a second ecosystem shows the same
  one-module-many-commands shape.
