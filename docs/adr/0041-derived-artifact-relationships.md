---
status: "accepted"
date: 2026-08-06
decision-makers: Patrick Fenerty
---

# Derived artifact relationships

## Context and Problem Statement

OCIDex tracks artifacts and the SBOMs that describe them, but it has no notion of one artifact
being *part of* another. Yet the relationship is already sitting in the data: when a container
image's SBOM is ingested, one of its components is the first-party binary we also track as an
artifact in its own right — same purl, same `(type, name, group)`. Nothing ever asks the
question, so the fact is never surfaced.

The user-facing payoff is drift. "`ocidex` v1.2.3 ships in four images, and one of them still
carries v1.2.1" is actionable, and today it is unanswerable without manually diffing four SBOMs.

How should artifact-to-artifact relationships be represented: stored at write time, declared by
the producer, or derived at read time from component data we already have?

## Decision Drivers

* Relationships must agree with diff on what counts as "the same thing". If the changelog says
  two components are one package across versions but the relationship view says they are two
  different artifacts, one of them is lying to the user.
* Version must remain *comparable*, not collapsed. Identity matching normally discards the
  version; here the version delta **is** the feature.
* No new ingest write path, and no backfill — relationships should appear retroactively for
  SBOMs already in the database.
* Must respect the namespace visibility model (ADR-025, ADR-039). A relationship must never leak
  the existence of an artifact in a namespace the caller cannot see.
* Must resolve *across sources within a namespace*: the uploaded binary and the scanned image are
  two ingest channels for one project (ADR-039), and the relationship spans them.

## Considered Options

* Stored `artifact_link` table, populated at ingest
* CI-declared links, where the build pipeline asserts "this image contains that binary"
* Derived at query time from component data

## Decision Outcome

Chosen option: **derived at query time from component data**, because the relationship is already
a fact of the ingested SBOM rather than new information, and deriving it keeps a single source of
truth. A stored table would need a write path, a backfill, and an invalidation story, and would be
able to disagree with the components it was derived from. CI-declared links would additionally
require every producer to cooperate before any relationship appears at all.

The rules below are normative.

### Rule R1 — Match key is ADR-019's identity key, reused verbatim

A component matches an artifact when their identity keys are equal, where the key is exactly the
one diff uses: `componentKey(type, name, group, purl)` in `internal/service/changelog.go`.

That means the layering of ADR-019 applies unchanged:

1. **purl base + identity qualifiers** when a purl is present — `@version` stripped, qualifiers
   filtered to the identity-bearing set (`distro` family-only, `arch`, `epoch`, `repository_url`)
   and sorted alphabetically. See ADR-019 Rule 1 for the full qualifier partition and the distro
   normalization rule.
2. **`(type, name, group)` tuple**, NUL-joined, when the component carries no purl.

This is a reuse requirement, not a restatement: relationship code MUST call the same function
rather than reimplement the layering. If the qualifier policy changes, both consumers must change
together. Divergence between the two is a bug in the relationship code, not a local variation.

### Rule R2 — Version is carried alongside the key, never inside it

R1's key is version-free by construction. The relationship query therefore compares versions as a
*separate* field: the matched `component.version` against the candidate artifact's
`sbom.subject_version`.

This is the one place where relationship semantics deliberately differ in emphasis from diff. Diff
strips the version in order to *pair* two components so it can report the change between them;
relationships strip the version in order to pair a component with an artifact so they can report
the drift between them. Same key, opposite framing of the leftover.

### Rule R3 — ADR-019 Rule 3 does NOT apply

ADR-019's versioned-name post-pass (collapsing `foo-1` / `foo-2` style pairs, guarded by the
survivor check) is explicitly **out of scope** here, for two reasons:

* It is a reconcile over a symmetric-difference change list. Relationship resolution produces no
  change list — there is nothing to reconcile.
* Applying it would actively cause wrong answers. `libfoo-1` and `libfoo-2` as two tracked
  artifacts are two artifacts; merging them would report an image as containing an artifact it
  does not contain.

Stating this explicitly because "match ADR-019" would otherwise reasonably be read as "apply all
three rules".

### Rule R4 — Only tracked artifacts participate

A component resolves to a relationship only when its key matches a row in the `artifact` table.
Components that match nothing are ordinary SBOM contents and stay that way. "First-party" is not a
separate flag — it is precisely the property of having been ingested as an artifact subject.

### Rule R5 — Two directions, both visibility-filtered

* **usages** — given artifact A, the artifacts whose latest SBOM contains a component matching A.
  "Where does this ship?"
* **contains** — given artifact A, the tracked artifacts matched by components of A's latest SBOM.
  "What of ours does this carry?"

Both directions filter through `visible_namespace_ids(user_id, is_admin)`, the same function the
stats queries use. Both resolve across sources within the visible namespaces.

### Consequences

* Good, because there is no write path, no migration, and no backfill: every SBOM already ingested
  gains relationships the moment the query exists.
* Good, because identity cannot drift from diff — it is the same function, not a parallel
  implementation of the same rules.
* Good, because deleting or re-ingesting an SBOM cannot leave a stale link behind.
* Bad, because the cost moves to read time. See the indexing caveat below.
* Bad, because we only ever see relationships the SBOM tooling recorded. A binary that the scanner
  did not emit as a component is invisible to this feature, and there is no way to assert the link
  manually — that is the deliberate trade of rejecting CI-declared links.

**Indexing caveat for implementors.** `idx_component_purl` and `idx_component_name_group` index
the *raw* column values, but R1's key is a normalized form computed in Go (version stripped,
qualifiers filtered and sorted). An equality lookup against the normalized key therefore cannot
use those indexes directly. Either match on a purl-base prefix — which a btree can serve — or add
an expression index. Do not assume the existing indexes make this query cheap.

### Confirmation

Endpoints land in `ocidex-rj4.2`. Confirmed by tests covering:

* a relationship resolved via purl-base match (R1 layer 1) and one resolved via the tuple fallback
  (R1 layer 2), proving both layers are wired;
* a version delta between component and artifact surfacing as drift rather than as a non-match
  (R2);
* two artifacts differing only by a numeric name suffix staying distinct (R3);
* a candidate in a non-visible namespace being absent from both directions (R5);
* a relationship spanning two sources within one namespace being present (R5).

## Pros and Cons of the Options

### Stored `artifact_link` table

* Good, because reads are a trivial indexed join.
* Good, because a link could carry metadata the component data cannot express.
* Bad, because it duplicates a fact already in `component`, and duplicated facts drift.
* Bad, because it needs a backfill for existing SBOMs and an invalidation path on re-ingest.
* Bad, because identity would be decided at write time, freezing whatever the qualifier policy
  happened to be that day — precisely the divergence-from-diff risk R1 exists to prevent.

### CI-declared links

* Good, because the producer knows the truth with certainty, including relationships no scanner
  could infer.
* Bad, because nothing appears until every producer opts in, and the feature is worthless while
  coverage is partial.
* Bad, because it couples OCIDex's data model to build-pipeline cooperation across repos.

### Derived at query time

* Good, because it is retroactive, self-invalidating, and shares identity logic with diff.
* Bad, because query cost is paid per request and the normalized key does not match the existing
  indexes.
* Bad, because coverage is limited to what the SBOM records.

## More Information

* Identity layering is normative in
  [ADR-0019 — Diff identity model](0019-diff-identity-model.md); this ADR reuses Rules 1–2 and
  explicitly excludes Rule 3.
* Visibility model: [ADR-0025 — RBAC and visibility](0025-rbac-visibility.md) and
  [ADR-0039 — Namespace and source model](0039-namespace-and-source-model.md).
* Non-container artifacts get their `purl` from the caller at upload time
  ([ADR-0040 — Non-container artifact identity](0040-non-container-artifact-identity.md)), which
  is what makes R1 layer 1 reachable for uploaded binaries at all.
* Relationship cards reuse the entry-card structure of
  [ADR-0023 — Visual identity](0023-visual-identity.md) and
  [ADR-0036 — DataTable cell renderer conventions](0036-datatable-cell-renderer-conventions.md).
* Epic: `ocidex-rj4` — Artifact relationships and type-aware UI.

### Non-goals

Recorded so they are not silently revisited:

* **A stored `artifact_link` table.** Reopen only if a relationship must carry state that is not
  derivable from component data — for example a human-asserted link, or a link that must survive
  the deletion of the SBOM that evidenced it.
* **CI-declared links.** Reopen only if a real relationship appears that component data cannot
  express at all, rather than merely expresses inconveniently.

Query cost alone is not a reason to reopen either: the first response to a slow relationship query
is an expression index, not a stored table.
