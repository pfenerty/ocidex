---
status: "accepted"
date: 2026-08-15
decision-makers: Patrick Fenerty
---

# Pagination convention

## Context and Problem Statement

OCIDex has sixteen paginated list endpoints. They arrived in two waves. The original wave used
offset pagination — `?limit=&offset=`, response `{total, limit, offset}` — with the total obtained
from a `COUNT(*) OVER()` window on the same query. A later wave (SBOM lists, artifact lists, SBOM
components) used keyset pagination — `?limit=&cursor=`, response `{limit, hasMore, nextCursor}` —
after deep-page `OFFSET` scans and per-page full-set counts became measurable on large SBOMs.

Nothing recorded *which* style a new endpoint should get. The result is that the split across the
sixteen endpoints reflects the order they were written, not any property of the data, and the
frontend has two paging idioms with no rule for choosing between them. Two endpoints — the
provenance drift feeds — are on the wrong side of any defensible rule: they are append-at-head
event streams ordered by `detected_at DESC` and paginated by offset, which is precisely the case
where offset silently duplicates and skips rows.

The question this ADR settles is not "which style is better" — both are correct implementations
with different trade-offs — but "what property of an endpoint decides its style", so that the
answer is derivable rather than remembered.

## Decision Drivers

* Correctness under concurrent writes: offset pagination shifts rows across page boundaries when
  the underlying set changes mid-scroll. This is a correctness bug for the user, not a
  performance one — rows are silently duplicated or skipped.
* Cost: `OFFSET n` scans and discards n rows; `COUNT(*) OVER()` materializes the full result set
  on *every* page. Both are per-page costs that grow with the set.
* Capability: only offset pagination can answer "how many in total" and "jump to page 7". Some
  UIs need those; discarding them is not free.
* Derivability: the rule must be decidable from the query's `ORDER BY` and the table's write
  pattern, without judgment calls.

## Considered Options

* **Keyset everywhere.** Uniform, always correct, cheapest. Costs the total count and random page
  access, which several UIs currently display.
* **Offset everywhere.** Uniform, keeps counts, and is what most endpoints already do. Reinstates
  the correctness bug on every append-at-head feed.
* **A decision procedure keyed on the ORDER BY and the write pattern.** Not uniform, but each
  endpoint's style is derivable, and the non-uniformity tracks a real difference between the
  endpoints.

## Decision Outcome

Chosen option: **a decision procedure keyed on the ORDER BY and the write pattern**, applied in
order. The first rule that matches decides.

### Rule 1 — a mutable column in the ORDER BY forces offset

If any column in the `ORDER BY` can change value for a row that already exists, keyset pagination
is **ill-defined**, not merely suboptimal. The cursor names a position in an ordering; if a row's
sort key mutates after the cursor is issued, the cursor points into an ordering that no longer
exists, and the comparison `(sort_key, id) < (cursor_key, cursor_id)` can exclude rows the client
has not seen and include rows it has. Offset is *also* wrong under mutation, but it degrades
gracefully — it stays a well-defined position in the current ordering — whereas keyset produces a
cursor with no meaning.

This is not hypothetical. `ListScanJobs` and `ListEnrichmentJobs` order by a state bucket:

```sql
ORDER BY CASE state WHEN 'running' THEN 1 WHEN 'queued' THEN 2 WHEN 'failed' THEN 3
                    WHEN 'succeeded' THEN 4 END, created_at DESC
```

A job moves from `queued` to `running` to `succeeded` while the operator is scrolling the job
list. Its sort key changes bucket under the cursor. These two endpoints stay on offset, and the
reason is structural, not historical.

### Rule 2 — rows appended at the head of an immutable ordering force keyset

If rows are inserted at the head of the ordering (`ORDER BY <insert-time column> DESC`) and the
ordering columns never change afterwards, offset pagination is wrong: every insert during the
scroll shifts the entire window by one, so page 2 re-shows the last row of page 1. Use keyset on
`(<time column> DESC, id DESC)`, with `id` as tiebreaker because timestamps are not unique.

This covers `sbom`, `artifact`, and `provenance_drift_events`. The last of these is what this ADR
fixes.

### Rule 3 — otherwise, the UI decides

What is left is sets that are frozen or slow-changing and ordered by a stable attribute (a name, a
severity, a license ID). Both styles are correct here; neither correctness argument bites. Decide
on the interaction the UI actually offers:

* Numbered pages, "N results", or a jump-to-page control ⇒ **offset**. These require a total, and
  the total is part of the answer the user asked for.
* A "Load more" / infinite-scroll control ⇒ **keyset**. No total is displayed, so paying
  `COUNT(*) OVER()` on every page buys nothing.

`ListSBOMComponents` lands here: an SBOM's component set is frozen once ingested, so offset would
be perfectly correct, but the UI is Load-more and displays no total — keyset, and it stays keyset.

### Consequences

* Good, because each endpoint's style is now derivable from its query rather than from the date it
  was written, and a new endpoint's style is a two-minute determination.
* Good, because the two drift feeds stop duplicating and skipping rows during active
  re-verification — the case where drift events are *most* likely to be appended mid-scroll.
* Bad, because the API is not uniform: clients must handle both `{total, limit, offset}` and
  `{limit, hasMore, nextCursor}`. This is accepted; the alternative is uniformity bought either by
  a correctness bug (Rule 2 cases on offset) or by deleting counts the UI displays (Rule 3 cases
  on keyset).
* Neutral: Rule 1 is a *constraint*, not a preference. If the jobs lists ever need keyset, the
  fix is to make the ordering immutable (order by `created_at` and filter by state), not to issue
  a cursor against a mutable key.

### Classification of the sixteen endpoints

| Endpoint | Ordering | Rule | Style |
|---|---|---|---|
| `GET /sbom` | `created_at DESC, id DESC` | 2 | cursor |
| `GET /sbom/{id}/components` | `name, group_name, id` | 3 (Load more) | cursor |
| `GET /sboms/{id}/drift` | `detected_at DESC, id DESC` | 2 | cursor *(changed)* |
| `GET /artifacts` | `created_at DESC, id DESC` | 2 | cursor |
| `GET /artifacts/{id}/sboms` | `created_at DESC, id DESC` | 2 | cursor |
| `GET /registries/drift-feed` | `detected_at DESC, id DESC` | 2 | cursor *(changed)* |
| `GET /components` | name/purl match | 3 (counted) | offset |
| `GET /components/distinct` | name/purl match | 3 (counted) | offset |
| `GET /licenses` | usage count DESC | 3 (counted) | offset |
| `GET /licenses/{id}/components` | component name | 3 (counted) | offset |
| `GET /artifacts/{id}/versions` | version sort mode | 3 (counted) | offset |
| `GET /vulns` | severity, findings DESC | 3 (counted) | offset |
| `GET /vulns/{id}` | affected artifact/component | 3 (counted) | offset |
| `GET /registries` | name | 3 (counted, bounded set) | offset |
| `GET /jobs` | **state bucket**, `created_at DESC` | 1 | offset |
| `GET /enrichment-jobs` | **state bucket**, `created_at DESC` | 1 | offset |

Only the two drift feeds changed. Every other endpoint was already on the side the procedure
selects — which is the evidence that the procedure describes the codebase's implicit rule rather
than imposing a new one.

## Implementation notes

Keyset endpoints embed `CursorParams` in their input and `CursorMeta` in their output body; offset
endpoints embed `PaginationParams` and `PaginationMeta` (`internal/api/types.go`). The cursor is
opaque base64(JSON) built by `encodeTimeIDCursor`/`decodeTimeIDCursor` (`internal/api/cursor.go`)
for `(time, id)` orderings; `encodeStringCursor`/`decodeStringCursor` covers the string-keyed case.

A keyset query takes `has_cursor`, the cursor columns, and `row_limit`, and the **service** asks
for `row_limit + 1` rows to derive `HasMore`, truncating before returning `CursorPage[T]`. The
extra row is why a keyset query needs no `COUNT(*) OVER()` at all. See
`db/queries/provenance_drift.sql` and `searchService.ListRecentProvenanceDrift` for the smallest
complete example.

Because the cursor is `(detected_at, id)`, `ProvenanceDriftSummary` carries an `ID`. It is
`omitempty` because `GetLatestProvenanceDrift` — the single-row lookup embedded in the SBOM detail
response — is not paginated and does not select it.
