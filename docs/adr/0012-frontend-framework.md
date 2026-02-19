---
status: "accepted"
date: 2025-06-09
decision-makers: Patrick Fenerty
---

# Choose a Frontend Framework

## Context and Problem Statement

OCIDex has a fully functional REST API but no user interface. We need to choose a frontend framework/library that aligns with the project's architectural principles: composable, idiomatic, minimal-abstraction designs that favor emerging technologies over entrenched incumbents. The UI will be a data-heavy dashboard for browsing SBOMs, artifacts, components, and licenses.

## Decision Drivers

* Fine-grained reactivity — minimal re-rendering for data-heavy tables and lists
* Small runtime footprint — aligns with the Go backend's "small and composable" ethos
* Composable primitives — prefer signals/reactive atoms over opaque framework magic
* Ecosystem maturity — must have a router, data fetching story, and component library options
* Emerging over entrenched — prefer forward-looking technology when quality is comparable
* TypeScript-first — type safety across the frontend codebase
* Single-binary deployment — frontend must be embeddable in the Go binary via `embed.FS`

## Considered Options

* SolidJS
* Svelte 5 (Runes)
* Preact + Signals
* React 19
* Vue 3 (Composition API)
* htmx + templ (Go server-rendered)

## Decision Outcome

Chosen option: "SolidJS", because it provides native fine-grained reactivity via signals with no virtual DOM overhead, compiles JSX to direct DOM updates (~7 KB runtime), and its composable primitives (`createSignal`, `createResource`, `createEffect`) align with the project's "small, composable, no-abstraction-tax" philosophy — the frontend equivalent of choosing chi over Echo.

### Consequences

* Good, because signals-based reactivity eliminates React's re-render, stale closure, and dependency array problems
* Good, because reactive primitives work in plain `.ts` files — not compiler-coupled like Svelte Runes
* Good, because JSX syntax is familiar to developers with React experience
* Good, because TanStack Query, TanStack Table, and Kobalte all have Solid adapters covering the project's needs
* Good, because pure SPA output is trivially embeddable via Go's `embed.FS`
* Neutral, because smaller ecosystem than React — but sufficient for a data dashboard
* Bad, because some React mental models don't transfer (props must not be destructured to preserve reactivity)
* Bad, because hiring pool is smaller if the project scales beyond solo development

### Confirmation

The chosen framework is used for all frontend components. No mixed-framework code. Bundle size and Lighthouse scores are tracked in CI.

## Pros and Cons of the Options

### SolidJS

* Good, because fine-grained reactivity via signals, derived, and effects — no virtual DOM, no diffing overhead
* Good, because compiles JSX to direct DOM updates — smallest possible runtime (~7 KB)
* Good, because composable primitives: `createSignal`, `createResource`, `createEffect` are orthogonal building blocks
* Good, because JSX syntax familiar to React developers — lower learning curve than template DSLs
* Good, because TypeScript-first with excellent type inference
* Good, because TanStack Query has an official Solid adapter
* Good, because Kobalte provides accessible headless UI primitives (Solid's equivalent of Radix)
* Neutral, because smaller ecosystem than React — fewer third-party component libraries
* Bad, because no Server Components or SSR framework comparable to Next.js (SolidStart is early)
* Bad, because hiring pool is smaller if the project grows beyond solo development
* Bad, because some React patterns don't transfer (destructuring props breaks reactivity)

### Svelte 5 (Runes)

* Good, because compiler eliminates runtime — output is vanilla JS (~4 KB overhead)
* Good, because Runes (`$state`, `$derived`, `$effect`) bring explicit reactivity, moving away from Svelte 4's implicit magic
* Good, because SvelteKit provides file-based routing, SSR, and data loading out of the box
* Good, because `.svelte` single-file components with scoped CSS by default
* Good, because growing ecosystem with mature component libraries (Melt UI, Skeleton)
* Neutral, because template DSL (not JSX) — different mental model, can't reuse JS expression patterns directly
* Bad, because reactivity is compiler-coupled — can't extract reactive primitives into plain `.ts` files as easily as signals
* Bad, because Runes are new (Svelte 5 released late 2024) — ecosystem is still migrating from Svelte 4 patterns
* Bad, because less composable than raw signals — the compiler does more, the developer controls less

### Preact + Signals

* Good, because 3 KB runtime with full React API compatibility via `preact/compat`
* Good, because `@preact/signals` adds fine-grained reactivity on top of the component model
* Good, because access to the entire React ecosystem (component libraries, tools, tutorials)
* Good, because drop-in replacement for React — easiest migration path if needs change
* Neutral, because signals are an add-on, not the core model — mixing hooks and signals can be confusing
* Bad, because `preact/compat` has edge cases where React libraries don't work perfectly
* Bad, because signals in Preact are less ergonomic than SolidJS signals (bolt-on vs native)
* Bad, because still uses virtual DOM reconciliation — signals reduce but don't eliminate diffing

### React 19

* Good, because largest ecosystem by far — any component library, tool, or tutorial exists
* Good, because Server Components and Actions in React 19 represent a major architectural shift
* Good, because massive hiring pool and community knowledge base
* Good, because TanStack Query, Radix, shadcn/ui, and every major library targets React first
* Bad, because ~40 KB runtime (ReactDOM) — largest of all options
* Bad, because hooks model is less composable than signals — `useEffect` dependency arrays are a known footgun
* Bad, because virtual DOM reconciliation is fundamentally less efficient than fine-grained reactivity
* Bad, because Server Components require a meta-framework (Next.js) to be useful — adds complexity
* Bad, because not "emerging" — represents the incumbent, not the frontier

### Vue 3 (Composition API)

* Good, because Composition API with `ref`/`reactive` is signal-adjacent reactivity
* Good, because mature ecosystem (Nuxt, Vuetify, PrimeVue, Pinia)
* Good, because single-file components with scoped styles
* Good, because template compiler optimizes static content hoisting
* Neutral, because ~33 KB runtime — smaller than React, larger than Solid/Svelte/Preact
* Bad, because template DSL adds a layer of abstraction over raw JS
* Bad, because Composition API, while improved, is still less composable than SolidJS signals
* Bad, because ecosystem momentum has plateaued relative to React and Svelte

### htmx + templ (Go server-rendered)

* Good, because zero JavaScript build step — Go templates rendered server-side
* Good, because single binary deployment is trivially simple
* Good, because hypermedia approach aligns with REST API philosophy
* Good, because `templ` provides type-safe Go templates with component composition
* Bad, because limited client-side interactivity — complex filtering, sorting, and real-time updates are awkward
* Bad, because every interaction requires a server round-trip — poor UX for data exploration
* Bad, because no ecosystem of pre-built interactive components (tables, charts, modals)
* Bad, because does not meet the "full-featured modern UX" requirement for a data-heavy dashboard

## More Information

* [SolidJS](https://www.solidjs.com/) — reactive primitives, JSX compilation
* [Svelte 5 Runes](https://svelte.dev/blog/runes) — compiler-driven reactivity
* [Preact Signals](https://preactjs.com/guide/v10/signals/) — fine-grained reactivity for Preact
* [React 19](https://react.dev/blog/2024/12/05/react-19) — Server Components, Actions
* [Vue 3 Composition API](https://vuejs.org/guide/extras/composition-api-faq.html)
* [htmx](https://htmx.org/) + [templ](https://templ.guide/)
