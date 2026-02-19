---
status: "accepted"
date: 2025-06-09
decision-makers: Patrick Fenerty
---

# Choose Frontend Code Organization and Project Structure

## Context and Problem Statement

OCIDex is a Go monorepo with `cmd/`, `internal/`, `pkg/`, `tests/`, and `docs/` at the top level. We need to decide where the frontend source lives, how it's organized internally, and how it integrates with the existing build pipeline (`Makefile`, Docker multi-stage, CI). Depends on ADR-0012 (SolidJS) and ADR-0014 (Vite + embed.FS).

## Decision Drivers

* Monorepo cohesion — frontend and backend should live in the same repository and be buildable with a single `make build`
* Clear boundary — frontend code should be isolated from Go code (no interleaving)
* Feature colocation — components, styles, tests, and types for a feature should live together
* Flat over nested — avoid deep directory hierarchies that obscure discoverability
* Convention alignment — follow SolidJS and Go monorepo community conventions
* Embed compatibility — the build output directory must be embeddable via Go's `embed.FS`

## Considered Options

* `web/` top-level directory with feature-based modules
* `frontend/` top-level directory with layer-based organization
* `ui/` as a separate Go module (workspace)
* Embedded in `internal/api/` alongside handlers

## Decision Outcome

Chosen option: "`web/` top-level directory with feature-based modules", because `web/` is the established convention for frontend code in Go monorepos, feature-based modules colocate everything for a domain (components, tests, types), the `dist/` output is a clean target for `embed.FS`, and the flat structure is easy to navigate.

### Consequences

* Good, because `web/` is immediately recognizable to Go developers as the frontend directory
* Good, because feature modules (`artifacts/`, `sboms/`, `components/`, `licenses/`) mirror the API's domain structure
* Good, because adding a feature means creating one directory with colocated component, test, and type files
* Good, because `web/dist/` is a clean, git-ignored output directory for `embed.FS`
* Good, because `shared/` provides a clear boundary for reusable layouts and primitives
* Neutral, because requires judgment on when something belongs in `features/` vs `shared/`
* Bad, because `web/src/features/components/` could be confused with the SBOM "components" domain — will use clear naming

### Confirmation

`ls web/src/features/` shows domain-aligned directories. `make build` compiles frontend and embeds output. New features can be added by creating a single directory.

## Pros and Cons of the Options

### web/ top-level with feature-based modules

```
web/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html
├── src/
│   ├── app.tsx
│   ├── api/
│   ├── features/
│   │   ├── artifacts/
│   │   ├── sboms/
│   │   ├── components/
│   │   └── licenses/
│   ├── shared/
│   └── styles/
├── dist/
└── tests/
```

* Good, because `web/` is the Go monorepo convention
* Good, because feature modules colocate everything for a domain
* Good, because `dist/` is a clean embed target
* Good, because flat feature directories are easy to navigate
* Neutral, because requires judgment on features/ vs shared/ boundary

### frontend/ top-level with layer-based organization

* Good, because layer-based organization is familiar
* Bad, because related code is scattered across layers — adding a feature touches 4+ directories
* Bad, because `frontend/` is less conventional than `web/` in Go projects
* Bad, because `components/` becomes a dumping ground

### ui/ as a separate Go module (workspace)

* Good, because clean module boundary
* Bad, because Go workspaces add complexity
* Bad, because overkill for a single frontend
* Bad, because `embed.FS` works across the repo anyway

### Embedded in internal/api/ alongside handlers

* Good, because frontend is next to the handlers that serve it
* Bad, because mixes Go and TypeScript/JSX
* Bad, because `internal/` implies Go private packages
* Bad, because pollutes Go package structure with `node_modules`

## More Information

* [Go embed.FS](https://pkg.go.dev/embed)
* [Feature-Sliced Design](https://feature-sliced.design/)
