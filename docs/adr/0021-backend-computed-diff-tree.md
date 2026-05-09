---
status: "accepted"
date: 2026-05-09
decision-makers: Patrick Fenerty
---

# Backend-Computed Diff Tree and Rollups

## Context and Problem Statement

The diff and dependency-tree views in `web/src/components/DiffTreeView.tsx` and `web/src/pages/SBOMDetail/PackagesTab.tsx` perform substantial work in the browser to turn the API response into a rendered tree:

* build a `nameMap` keyed on multiple identifiers (id, name, purl, base purl, bom-ref) so changes can be cross-referenced to graph nodes;
* build the adjacency list and the inverse to find roots;
* fall back to "first 10 fromRefs" when no clean root exists (today's silent-failure mode);
* run a DFS to mark each ancestor as `hasChangedDesc`;
* run `classifyChange` on every render, which calls `debVersionCompare` (epoch + segment-aware deb version comparison reimplemented in TypeScript);
* re-derive added / removed / upgraded / downgraded counts on every reactive update.

The `DiffTree` response carries enough raw data to do all this — `nodes`, `edges`, `changes` — but everything *interesting* about it (which nodes are roots, which changes belong to which node, which subtree contains what) is recomputed on each render. The previous attempts at smooth animation and expand-all (`ocidex-0ji`) crashed the browser specifically because the per-row reactive cost compounded with this client-side processing.

The goal is to push the heavy lifting onto the backend so the frontend becomes a thin renderer. This ADR sets the contract.

## Decision Drivers

* **Single source of truth.** Identity rules ([ADR-0019](0019-diff-identity-model.md)) and flavor detection ([ADR-0020](0020-image-flavor-axis.md)) live on the backend. The diff tree's structure should follow the same principle: computed once, server-side, in Go that can be tested.
* **Frontend simplicity.** SolidJS components should describe what to render, not how to compute it. Today's `DiffTreeView` is roughly 50% computation and 50% rendering; the target is ~5% / 95%.
* **Reactive cost.** Every client-side computation runs on every reactive update. Eliminating them frees the budget for genuinely interactive work — expand-all, virtualization (`bqh.19`–`bqh.21`).
* **Determinism and testability.** A single Go function that produces the tree is straightforward to unit-test against fixture SBOMs. Cross-component reactive computations are not.
* **Stable cross-references.** Today the frontend probabilistically links changes to graph nodes via overlapping name/purl/bom-ref maps. The backend has the authoritative join.
* **Bandwidth budget.** Backend pre-computation must not bloat the response so much that the win is erased. The schema below adds small per-node and per-change fields, not duplicated payloads.

## Considered Options

1. **Status quo — frontend computes the tree.** Today's behavior.
2. **Add a separate `/diff-tree/structured` endpoint** that returns a fully assembled tree object (nodes nested under their parents) and leave the existing endpoint alone.
3. **Enrich the existing `DiffTree` response (chosen).** Keep the flat `nodes` / `edges` / `changes` shape — which is well-suited to virtualization later — but populate every field the frontend would otherwise have to derive.

## Decision Outcome

Chosen: **option 3, enrich the existing `DiffTree` response in place**. Adding fields is backwards-compatible (frontend ignores unknown fields; older clients keep working until they're deleted). Keeping the shape flat preserves the option to render with row windowing (`bqh.20`) without restructuring the API.

The contract below is normative. Implementations live in `internal/service/changelog.go` (`DiffSBOMsWithTree`) and `internal/service/search.go` (graph endpoints used by `PackagesTab`). Any deviation between the code and this ADR is a bug in one of them.

### Contract — what the backend computes

The `DiffTree` response gains the following fields. Each one corresponds to a beads issue that lands the implementation:

#### 1. `roots []string` (new top-level field) — `bqh.12` (B5)

Ordered list of node refs that the UI should render as top-level rows. Computation:

1. If the SBOM's `metadata.component.bom-ref` appears in the dependency graph, the roots are its outgoing-edge targets (i.e., the image's direct dependencies). The synthetic root itself is not a row.
2. Otherwise, roots are nodes with zero in-edges in the graph (today's heuristic, but server-side and authoritative).
3. If both fail (cyclic graph with no clean root), `roots` is an empty array. The frontend MUST render an empty state — no "first 10 fromRefs" fallback.

The order of `roots` is stable: alphabetical by display name, with `metadata.component.bom-ref`-anchored roots ordered by their appearance in the dependency declaration when available.

#### 2. `ComponentSummary.isDirect bool` (new field on each node) — `bqh.13` (B6)

True iff the node is reachable in exactly one hop from `metadata.component.bom-ref`. False otherwise (and false for every node when no synthetic root is present). Used by the show-transitive toggle (`bqh.23`, D5) and by the direct-default tree view (`bqh.35`, G1).

#### 3. `ComponentDiff.direction string` (new field on each change) — `bqh.8` (B1)

One of `added`, `removed`, `upgraded`, `downgraded`, `modified`. Computed server-side using a deb-version-aware comparator that handles epochs (`1:2.0` > `2.0`), tildes (`1.0~rc1` < `1.0`), and mixed alpha/numeric segments. Replaces the frontend `classifyChange` + `debVersionCompare`. The frontend's role is reduced to choosing a badge color from this single field.

#### 4. `ComponentDiff.nodeRef *string` (new field on each change) — `bqh.10` (B3)

When the changed component is present in the graph (i.e., on the "to" side and in `nodes`, or on the "from" side and we synthesize a node for it), `nodeRef` is the matching node's primary key. The frontend uses this for an O(1) lookup when rendering the change at the correct tree position. Null when the change has no graph node (orphan removed packages, see below).

The match is computed using the identity rules from [ADR-0019](0019-diff-identity-model.md). The backend has the authoritative join because it has the identity-bearing qualifier policy already implemented.

#### 5. `ComponentSummary.descendantChanges *ChangeCounts` (new field on each node) — `bqh.11` (B4)

Per-node aggregate over the node's transitive descendants in the graph:

```go
type ChangeCounts struct {
    Added      int `json:"added"`
    Removed    int `json:"removed"`
    Upgraded   int `json:"upgraded"`
    Downgraded int `json:"downgraded"`
    Modified   int `json:"modified"`
}
```

Computed by a single DFS at the tree root using a visit-once Set keyed on node ref (cycle handling: descendants are counted once per ancestor even when reached via multiple paths). Drives the per-ancestor rollup chips (`bqh.17`, C3) so that "↑3 ↓1 +2" can render on a collapsed branch without the frontend re-walking the graph on every render.

`descendantChanges` is `nil` (omitted) when all counts are zero. This keeps the wire payload small for the common case of a clean leaf.

#### 6. `Summary` expansion — `bqh.9` (B2)

`ChangeSummary` today is `{added, removed, modified}`. Extend to `{added, removed, upgraded, downgraded, modified}`. Frontend stops re-running `classifyChange` to derive upgraded/downgraded counts from the change list.

#### 7. `removedOrphans []ComponentDiff` (new top-level field) — implicit in `bqh.12` (B5)

Removed packages that have no node in the graph (the "from" SBOM had them, the "to" SBOM doesn't, and they don't appear in the "to" dependency graph by construction). Today the frontend computes this set itself by checking purl/name presence in `inGraphPurls`. Move it server-side: the backend already has both component sets and can produce the orphan list authoritatively.

### What the frontend keeps doing

* Render rows from `roots[]` and `nodes[ref]`, recursing into `edges` for children.
* Manage UI state: which rows are expanded (centralized state, `bqh.19`), which toggles are on, view mode.
* Format strings (dates, version arrows, badge labels).
* Filter/search within the rendered tree.

That's it. No identity matching, no version comparison, no DFS, no root detection.

### Backwards-compatibility and migration

The new fields are additive. Old clients ignore them. The frontend simplification (`bqh.15`–`bqh.18`, phase C) lands *after* the backend changes (`bqh.8`–`bqh.14`, phase B) so there is never a window where the frontend depends on a field the backend hasn't shipped. `bqh.14` (B7) regenerates `web/openapi.json` and the typed client, making the new fields visible to TypeScript.

### Cycle handling — normative

The dependency graph can contain cycles (rare but possible: circular dev dependencies, certain language ecosystems). All backend traversals use a visit-once Set keyed on node ref. Specifically:

* `roots` computation does not depend on traversal — it's a property of the edge set.
* `isDirect` is computed by examining only the immediate outgoing edges of the synthetic root; no traversal needed.
* `descendantChanges` DFS visits each node at most once *per ancestor*. A node reachable from ancestor A via two paths counts once toward A's `descendantChanges`. The visit set is reset for each ancestor.
* `nodeRef` resolution does not traverse — it's a hash join on identity keys.

When a cycle would cause an ambiguity (e.g., two equally valid root candidates inside a cycle), the deterministic ordering rule from #1 above resolves it. The cycle itself is not surfaced — the UI shows the cycle members as siblings under whichever root reaches them first in a deterministic DFS.

### Performance budget

The new fields are O(nodes) in storage and O(nodes + edges) in computation, both of which the backend already pays to materialize the response. The wire-format growth is bounded:

* `isDirect`: 1 bool per node.
* `direction`: 1 short string per change (subsumes `type` semantically, but kept alongside for backwards compat).
* `nodeRef`: 1 string per change (already-present data, just a join result).
* `descendantChanges`: 5 ints per non-leaf node, omitted on leaves and on zero-aggregates.
* `roots`: 1 array of strings, typically <50 items.

For a typical 500-component SBOM with 50 changes, the additions are ~3 KB on top of a ~200 KB payload — under 2%. We accept this.

### Consequences

* Good: frontend gets ~50% smaller and substantially less reactive work per render.
* Good: the diff tree's behavior is testable end-to-end in Go fixtures (`bqh.36`, G2; `bqh.27`, E3) without a browser.
* Good: rollup totals reconcile with what the user sees, by construction — they come from the same DFS.
* Good: the show-transitive and expand-all-changed features (D5, D3) become trivial because their inputs are already on the response.
* Neutral: a handful of API fields are added; OpenAPI spec grows correspondingly.
* Bad: any future change to the response shape now requires touching Go and TypeScript instead of just TypeScript. We accept this — the cost of inconsistency between the two is higher than the cost of coordinated changes.
* Bad: very small SBOMs (10 components) pay a tiny fixed cost for fields that wouldn't be needed if the frontend were doing the work. Negligible.

### Confirmation

Confirmed by:

* `bqh.36` (G2) — fixture-driven tests for `roots[]` across SBOMs from Syft, Trivy, apko, and hand-written CycloneDX.
* `bqh.27` (E3) — golden-file tests for `nodeRef` resolution under the identity rules.
* `bqh.34` (F7) and integration tests — end-to-end response shape including all new fields.
* `bqh.16` (C2) — frontend renders directly from the new fields with no derivation logic; visual parity verified manually before merge.

## Pros and Cons of the Options

### Option 1 — Status quo

* Good: zero migration work.
* Bad: every UI improvement (rollups, expand-all, show-transitive) requires more frontend logic on top of the existing pile.
* Bad: the version-comparison code is duplicated between Go (`compareVersionStrings`) and TypeScript (`debVersionCompare`); they will drift.
* Bad: the spike `ocidex-0ji` documents that the current architecture cannot support smooth animation or expand-all without crashing the browser. Adding more client-side work makes this worse.

### Option 2 — Separate structured endpoint

* Good: keeps the flat endpoint untouched for any caller that prefers it.
* Bad: two endpoints to maintain, two response shapes, two test suites.
* Bad: a structured (nested) tree response works against virtualization — windowing wants a flat list.
* Bad: encourages "old endpoint for old features, new endpoint for new features" splits that proliferate.

### Option 3 — Enrich the existing response (chosen)

* Good: one source of truth for the tree contract.
* Good: additive — old clients keep working.
* Good: preserves the flat shape that's friendly to row virtualization.
* Bad: every consumer of `DiffTree` is exposed to the new fields whether they need them or not (acceptable; there are very few consumers).

## More Information

* Identity rules consumed by `nodeRef` resolution: [ADR-0019 — Diff identity model](0019-diff-identity-model.md).
* Flavor axis (orthogonal to tree structure but related): [ADR-0020 — Image flavor detection from SBOM contents](0020-image-flavor-axis.md).
* Tree-perf spike documenting why client-side computation must shrink: `ocidex-0ji`.
* Phase B issues (backend implementation): `bqh.8`–`bqh.14`.
* Phase C issues (frontend simplification, depends on B): `bqh.15`–`bqh.18`.
* Phase D issues (tree controls, depends on C): `bqh.19`–`bqh.24`.
* Epic: `ocidex-bqh` — Diff & tree display: backend-computed, flavor-aware.
