---
status: "accepted"
date: 2025-06-09
decision-makers: Patrick Fenerty
---

# Choose Build Tooling and Deployment Strategy for Frontend

## Context and Problem Statement

The frontend needs a build tool to compile TypeScript/JSX, bundle modules, and optimize assets for production. Additionally, we need to decide how the built assets are served. The API and frontend should run as independent services — the Go binary is a pure API server and the SPA is served separately. This decision affects the development workflow, CI pipeline, and deployment model. Depends on ADR-0012 (SolidJS).

## Decision Drivers

* Independent deployability — API and frontend have different release cadences and scaling needs
* Fast dev feedback loop — hot module replacement (HMR) during development
* Production optimization — tree-shaking, code splitting, minification, asset hashing
* CI simplicity — frontend and backend builds are independent, parallelizable pipelines
* Minimal configuration — convention over configuration, zero-config where possible
* Framework compatibility — must support SolidJS JSX compilation via `vite-plugin-solid`
* Clean separation — Go binary is a pure API server with no static-file concerns

## Considered Options

* Vite + separate container (nginx)
* Vite + Go `embed.FS` (single binary)
* esbuild + separate container
* Turbopack + separate container

## Decision Outcome

Chosen option: "Vite + separate container (nginx)", because it cleanly separates the API and frontend into independently deployable services. Vite is the recommended build tool for SolidJS with an official plugin (`vite-plugin-solid`), provides near-instant HMR in development, and produces optimized production bundles via Rollup. The built SPA is served by nginx in its own container with proper SPA fallback routing, cache headers, and gzip compression. The Go binary remains a pure API server with no frontend coupling.

### Consequences

* Good, because `vite-plugin-solid` handles JSX compilation with zero configuration
* Good, because HMR provides sub-second feedback during development
* Good, because Rollup-based production builds produce hashed, tree-shaken, code-split bundles
* Good, because API and frontend can be deployed, scaled, and updated independently
* Good, because Go binary stays lean — no embedded assets, no static-file serving logic
* Good, because nginx provides production-grade static serving with gzip, cache headers, and HTTP/2
* Good, because frontend and backend CI pipelines are independent and can run in parallel
* Neutral, because two containers instead of one — marginal operational overhead for docker-compose
* Bad, because CORS must be configured on the API to allow cross-origin requests from the frontend origin

### Confirmation

`docker-compose up` starts postgres, the API, and the web frontend as three separate services. `make frontend-dev` runs the Vite dev server proxying API requests to the Go backend. `make build` builds only the Go binary with no frontend dependency.

## Pros and Cons of the Options

### Vite + separate container (nginx)

* Good, because API and frontend are independently deployable, scalable, and versioned
* Good, because Go binary is a pure API server — no static-file complexity
* Good, because nginx is a battle-tested static file server with gzip, HTTP/2, and edge caching
* Good, because Vite HMR provides sub-second dev feedback
* Good, because CI pipelines for frontend and backend are independent
* Neutral, because two containers instead of one — trivial with docker-compose
* Bad, because CORS configuration is required between services

### Vite + Go embed.FS (single binary)

* Good, because single-binary deployment — no separate static file server needed
* Good, because Vite HMR works in development via proxy
* Neutral, because frontend must be built before `go build` — CI must respect ordering
* Bad, because couples frontend and backend release cycles
* Bad, because Go binary grows with frontend asset size
* Bad, because `embed.FS` is read-only — no runtime configuration injection
* Bad, because any frontend change requires a full Go rebuild and redeploy

### esbuild + separate container

* Good, because esbuild is the fastest bundler — sub-second builds
* Bad, because no HMR — must use manual reload
* Bad, because no code splitting support
* Bad, because no plugin ecosystem — SolidJS JSX transform requires custom setup

### Turbopack + separate container

* Good, because Rust-based — fast incremental builds
* Bad, because tightly coupled to Next.js — standalone use is unsupported
* Bad, because no SolidJS support
* Bad, because not production-ready as a standalone bundler

## More Information

* [Vite](https://vitejs.dev/)
* [vite-plugin-solid](https://github.com/solidjs/vite-plugin-solid)
* [nginx](https://nginx.org/)