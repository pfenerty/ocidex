---
status: "accepted"
date: 2025-06-09
decision-makers: Patrick Fenerty
---

# Choose State Management, Routing, and Data Fetching Strategy

## Context and Problem Statement

The frontend needs to fetch data from the OCIDex REST API, manage client-side state (filters, selections, pagination), and handle navigation between views (artifact list, SBOM detail, component search, license browser). These three concerns are tightly coupled — the router drives which data to fetch, data fetching populates state, and state changes may trigger navigation. This ADR addresses all three as a unified decision. Depends on ADR-0012 (SolidJS).

## Decision Drivers

* Colocation — data fetching logic should live near the components that consume it
* Caching and deduplication — avoid redundant API calls when navigating back to previously visited views
* URL-driven state — filters and pagination should be reflected in the URL for shareability and back-button support
* Type safety — route params and API responses should be fully typed
* Minimal boilerplate — prefer convention and composition over configuration
* Framework alignment — use libraries designed for SolidJS, not adapters

## Considered Options

* `@solidjs/router` + TanStack Query Solid + raw signals
* `@solidjs/router` + `createResource` (built-in) + raw signals

## Decision Outcome

Chosen option: "`@solidjs/router` + TanStack Query Solid + raw signals", because TanStack Query's caching, background refetch, pagination support, and devtools are essential for a data-heavy dashboard with paginated lists across artifacts, SBOMs, components, and licenses. Raw signals (`createSignal`) handle local UI state (filters, selections) without a global state library — the TanStack Query cache serves as the de facto global state for server data.

### Consequences

* Good, because TanStack Query deduplicates concurrent requests and caches responses — navigating back to a list doesn't re-fetch
* Good, because `staleTime` and background refetch keep data fresh without manual invalidation
* Good, because `@solidjs/router` route params are reactive signals — components update granularly on navigation
* Good, because URL search params via `useSearchParams` keep filters shareable and back-button friendly
* Good, because no global state library needed — TanStack Query for server state, signals for UI state
* Neutral, because TanStack Query adds ~12 KB to the bundle
* Bad, because two data fetching primitives exist (createResource and TanStack Query) — team must use TanStack Query consistently

### Confirmation

All API calls use TanStack Query hooks. No raw `fetch` in components. Route params are typed. Browser back/forward works correctly across all views.

## Pros and Cons of the Options

### @solidjs/router + TanStack Query Solid + raw signals

* Good, because `@solidjs/router` is the official SolidJS router with tight reactivity integration
* Good, because TanStack Query Solid provides caching, background refetch, pagination, and devtools
* Good, because route params are reactive signals — granular updates on navigation
* Good, because `useSearchParams` syncs filter/pagination state to the URL
* Good, because raw signals are sufficient for local UI state — no additional state library
* Neutral, because two data fetching options exist in the ecosystem (createResource vs TanStack Query)
* Bad, because TanStack Query adds a dependency and concepts (query keys, cache invalidation)

### @solidjs/router + createResource + raw signals

* Good, because `createResource` is built-in — zero additional dependencies
* Good, because simpler API for basic fetch patterns
* Bad, because no shared cache — each resource manages its own state
* Bad, because no background refetch or stale-while-revalidate
* Bad, because manual pagination management — no `keepPreviousData` or infinite queries
* Bad, because no devtools for cache inspection

## More Information

* [SolidJS Router](https://docs.solidjs.com/solid-router)
* [TanStack Query Solid](https://tanstack.com/query/latest/docs/solid/overview)
* [SolidJS createResource](https://docs.solidjs.com/reference/basic-reactivity/create-resource)
