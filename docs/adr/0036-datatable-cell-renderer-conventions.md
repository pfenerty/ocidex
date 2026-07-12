---
status: "accepted"
date: 2026-07-12
decision-makers: Patrick Fenerty
---

# Shared DataTable Component and Cell-Renderer Conventions

## Context and Problem Statement

Every list page in OCIDex (`Components.tsx`, `Vulnerabilities.tsx`, `Licenses.tsx`,
`Artifacts.tsx`, `SBOMDetail/PackagesTab.tsx`) hand-rolls its own `<table>` markup. Only
`Components.tsx` implements sortable column headers (a `th-sortable` class, a `toggleSort`
handler, and a `sortArrow` indicator); the others render static, unsorted `<th>` headers, and
`PackagesTab.tsx` falls back to a one-off client-side `.sort()` helper with no header affordance
at all. Pagination is similarly split without a documented rule: `Pagination.tsx` (offset-based)
and `LoadMore.tsx` (cursor/keyset-based) are both in active use, but nothing says which a new page
should reach for. Loading/error/empty handling is centralized in `Feedback.tsx`'s `QueryResult`
wrapper, but tables don't use it consistently, and none distinguish a first load from a refetch —
every state transition swaps to a full-page spinner, causing layout shift on every sort or page
change. The result is that table behavior is inconsistent today, not just duplicated, and there is
no single place to add it correctly for new pages (per ADR-0015, sort/filter/pagination state was
already flagged as "custom-coded rather than framework-managed").

This ADR defines the normative contract for a shared `DataTable` component and a cell-renderer
catalog so that `ocidex-dbg.3` (build `DataTable.tsx`) and `ocidex-dbg.4` (build
`components/cells/`) have a spec to implement against, and so that later migration stories
(`ocidex-dbg.6`–`.13`) migrate every list page to the same behavior. No component code changes in
this story — spec only.

## Decision Drivers

* Consistency — every table should sort, paginate, and handle loading/error/empty the same way.
* Minimal new surface — codify the pattern `Components.tsx` already proves out; don't invent a
  new abstraction from scratch.
* No framework adoption — stays within ADR-0015's decision (plain Tailwind-styled `<table>`, no
  TanStack Table).
* No new design tokens — reuse the token set already established by ADR-0023.
* Low migration cost — column-driven API so existing pages can adopt it incrementally.

## Considered Options

* Column-driven `DataTable` component (generalizes the existing `Components.tsx` pattern)
* Per-page copy-paste of the `Components.tsx` sort/pagination logic (status quo)
* Adopt TanStack Table (headless table library)

## Decision Outcome

Chosen option: **column-driven `DataTable` component**, because it generalizes a pattern already
proven in production (`Components.tsx`), requires no new dependency, and keeps full control over
markup/styling as established by ADR-0015. TanStack Table was rejected in ADR-0015 already and
nothing here changes that calculus. Copy-paste was rejected because it's the source of today's
inconsistency.

### Column model

```ts
interface Column<T> {
  header: string;
  sortKey?: string;       // omit for non-sortable columns
  align?: "left" | "right"; // default "left"
  render: (row: T) => JSX.Element;
}
```

`DataTable<T>` takes `columns: Column<T>[]` and `rows: T[]`, plus the sort/pagination/feedback
props below. It owns rendering `<table>`/`<thead>`/`<tbody>` and the sortable-header affordance;
it does not own data fetching.

### Sort contract

Controlled and server-side by default, matching `Components.tsx`'s existing `sort`/`sort_dir`
query-param pattern: clicking a sortable header calls an `onSort(sortKey, dir)` prop; the parent
owns the sort signal and re-queries. Toggling behavior matches the existing implementation
(`Components.tsx:41-49`): clicking the active column flips its direction; clicking a new column
resets direction to the column's default.

An optional client-side sort mode is available for pages with a small, already-fully-loaded
dataset and no pagination-driving sort today (e.g. `Licenses.tsx`) — `DataTable` sorts `rows` in
place instead of calling `onSort`. A table is in exactly one mode, chosen by whether `onSort` is
provided.

**Default sort direction**, matching `Components.tsx`'s existing rule: text/name columns default
to ascending; numeric columns default to descending.

### Pagination / LoadMore slot

`DataTable` accepts exactly one of two mutually exclusive props:

* `pagination: { pagination: PaginationMeta; onPageChange: (offset: number) => void }` — renders
  `Pagination.tsx`. Use for server-side queries that return a known `total` (offset-based).
* `loadMore: { hasMore: boolean; loading: boolean; onClick: () => void }` — renders
  `LoadMore.tsx`. Use for keyset/cursor-paginated lists where a total count isn't available or
  isn't cheap to compute (this is why `Artifacts.tsx` already uses it).

Providing neither renders no pagination control (for the client-side-sort/no-pagination case).
Providing both is a contract violation.

### Feedback states

Loading/error/empty states are wired through `Feedback.tsx`'s existing `QueryResult<T>` (or the
three primitives it wraps — `Loading`, `ErrorBox`, `EmptyState`), not reimplemented per page.

`DataTable` distinguishes two loading situations:

* **First load** (no prior data for this query): render the full-page `Loading` spinner, as today.
* **Refetch** (sort or page change while prior rows are still available): render **skeleton
  rows** — placeholder `<tr>`s shaped by the current `columns` (one skeleton `<td>` per column,
  matching `align`), replacing row content only. The header, pagination control, and page chrome
  stay mounted. This avoids the layout shift of swapping the whole table region to a spinner on
  every interaction. Skeleton row count matches the page size (or the last-seen row count,
  whichever is smaller) so the table doesn't visibly resize.

Error and empty states are unchanged from current practice (`ErrorBox`, `EmptyState`).

### Defaults

* Default page size: **50**, matching `Components.tsx`'s current `limit = 50`.
* Default sort direction: **ascending** for text columns, **descending** for numeric columns.

### Cell-renderer catalog

Principle: **same data → same component everywhere.** A future `components/cells/` module
(`ocidex-dbg.4`) is an organizing/re-export layer over cell-shaped components that already exist —
it does not reimplement them:

| Data | Component | Location |
|---|---|---|
| Package URL | `PurlLink` | `web/src/components/PurlLink.tsx` |
| Vulnerability severity/id | `VulnBadge` family, `VulnId` | `web/src/components/VulnBadge.tsx`, `VulnId.tsx` |
| Artifact/purl type | `TypeBadge` | `web/src/components/ui/TypeBadge.tsx` |
| Signing status | `SigningBadge` | `web/src/components/ui/SigningBadge.tsx` |
| Generic badge | `Badge` | `web/src/components/ui/Badge.tsx` |
| License category | `CATEGORY_COLORS` map | `web/src/utils/licenseUtils.ts` |
| Timestamp | `formatDateTime` | `web/src/utils/format.ts:131` |

New cell types introduced by this epic (e.g. `ComponentNameCell`, `VersionCell`, `LicenseCell`,
`TimestampCell`, and the reserved `GitCommitCell` for `ocidex-dbg.13`) follow the same rule once
built: one canonical component per data type, used via `column.render` in every table that
displays that data.

### Consequences

* Good, because every migrated page gets consistent sort/paginate/loading behavior for free, and
  new pages have one component to reach for instead of copy-pasting `Components.tsx`.
* Good, because the skeleton-row refetch state removes a layout-shift papercut that exists on
  every current table today, at documentation cost only in this story.
* Good, because it's additive — no ADR-0015 decision is reversed, no new dependency, no new design
  tokens.
* Neutral, because pages with unusual table shapes (e.g. `PackagesTab.tsx`'s tree view) may only
  partially adopt `DataTable` (e.g. its flat list, not its tree) — this is expected and handled
  per-migration-story, not solved generically here.
* Bad, because the pagination-vs-loadMore choice is a per-page judgment call (based on whether a
  cheap total count exists) rather than something `DataTable` can infer automatically — a reviewer
  must check this at migration time.

### Confirmation

Each migration story (`ocidex-dbg.6`–`.13`) is confirmed against this ADR by checking: sortable
columns use the `onSort`/default-direction contract above; pagination uses `Pagination` for
known-total queries and `LoadMore` otherwise, never both; loading state distinguishes first-load
spinner from refetch skeleton rows; and no cell type is reimplemented where a cataloged component
already exists.

## Pros and Cons of the Options

### Column-driven `DataTable` component

* Good, generalizes a pattern already proven in `Components.tsx`.
* Good, no new dependency, full markup/styling control (consistent with ADR-0015).
* Good, incremental migration — pages adopt it one at a time.
* Bad, requires a real migration effort across 6+ pages (tracked as separate stories).

### Per-page copy-paste (status quo)

* Good, zero migration cost — nothing to build.
* Bad, this is the problem this ADR exists to fix: inconsistent sort/pagination/loading behavior
  across pages today.

### Adopt TanStack Table

* Good, framework-managed sort/filter/pagination state.
* Bad, already rejected in ADR-0015 in favor of plain Tailwind-styled tables; adopting it now
  would reverse that decision for no new justification.

## More Information

* `web/src/pages/Components.tsx:9-58` — reference implementation this ADR generalizes.
* `web/src/components/Pagination.tsx`, `web/src/components/LoadMore.tsx` — existing pagination
  components reused by `DataTable`.
* `web/src/components/Feedback.tsx` — existing loading/error/empty primitives (`QueryResult`).
* ADR-0015 — UI component library and styling; this ADR extends its "custom-coded sort/filter/
  pagination" consequence with a documented, shared pattern.
* ADR-0023 — Visual identity; this ADR introduces no new design tokens, reusing the existing set.
* Implementation: `ocidex-dbg.3` (`DataTable.tsx`), `ocidex-dbg.4` (`components/cells/`).
