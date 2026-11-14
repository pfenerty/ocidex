---
status: "accepted"
date: 2026-11-14
decision-makers: Patrick Fenerty
---

# Public docs site: Astro Starlight in `site/`, GitHub Pages at docs.ocidex.app, published by Tekton

## Context and Problem Statement

OCIDex 1.0 shipped with no user-facing documentation. `docs/` holds about 24 markdown files that
mix operator, contributor and end-user material, next to about 55 ADRs. Someone deciding whether
to adopt OCIDex has nowhere to start, and an operator has to know which of DEPLOYMENT,
CONFIGURATION, UPGRADING, SIZING and OPERATIONS to read.

The epic ocidex-mxy0 asks for a public docs site, separate from the app, for four audiences:
evaluators, operators, end users and integrators. Contributor material (DEVELOPMENT, FRONTEND_DEV,
K8S_DEV, RELEASING, CI_TEKTON, the ADRs) stays in the repo.

Which generator, where does the source live, where is it hosted, how is it structured and
versioned, which pages are generated, and which CI builds and publishes it?

## Decision Drivers

* **No runtime.** The site is static files. Nothing new to run, patch or page on.
* **Reference pages can't drift.** Where a source of truth exists (OpenAPI, config struct, CLI,
  auth rules, Helm values), the page is generated from it and CI fails when it is stale, the same
  contract as `openapi-check` and `auth-matrix-check`.
* **Lives with the code.** A PR that changes behaviour can change its docs in the same diff.
* **One CI system.** Everything else runs on Tekton Pipelines as Code (CI_TEKTON). The repo has no
  GitHub Actions, and a second CI system for one job is a second set of conventions to keep.
* **Fits the team's stack.** TypeScript and Vite are already in the repo (`web/`, `.tektonic/`).
* **Search, dark mode, phone width** out of the box, matching what the app already does.

## Considered Options

Generator:

* Astro Starlight
* Docusaurus
* MkDocs Material
* VitePress

Publishing:

* Tekton (PaC) builds, and pushes the output to a `gh-pages` branch
* A GitHub Actions workflow with `actions/deploy-pages`
* Serve the site from the homelab cluster next to the app

## Decision Outcome

Chosen: **Astro Starlight**, source in **`site/`** in the ocidex repo, hosted on **GitHub Pages at
`https://docs.ocidex.app`**, built and published by **Tekton** pushing to a `gh-pages` branch.

### Location and build

* `site/` is its own npm package (its own `package.json` and lockfile, outside the `web/`
  workspace) so the docs toolchain never shares a dependency tree with the app.
* `make docs` builds, `make docs-dev` serves locally, `make docs-generate` writes the generated
  pages, and `make docs-generate-check` fails on any diff (both checks are in `make check`).
* Internal links are validated at build time (`starlight-links-validator`); a broken internal link
  fails the build. External links are not checked in CI: they fail for reasons the PR didn't cause.

### Information architecture (Diataxis)

| Section | Audience | Contents |
| --- | --- | --- |
| Landing page | Evaluator | Problem, what OCIDex does, capabilities with screenshots, comparison with similar tools |
| Get started | Evaluator | Quickstart: demo stack to a browsed SBOM, its vulnerabilities and a diff |
| Concepts | Everyone | Artifacts, SBOMs and components, enrichment, vulnerability matching, diffs, namespaces and visibility, registries and sources, clusters and coverage |
| Guides: Operate | Operator | Install with Helm, configure, auth providers, registries, workers, upgrade, back up, size, troubleshoot, verify release artifacts |
| Guides: Use | End user | Ingest, browse, diff, vulnerabilities, labels, clusters, namespaces and API keys, notifications |
| Guides: Integrate | Integrator | API authentication and versioning, ocidex-cli, MCP, CI recipes (GitHub Actions, Tekton, GitLab) |
| Reference | Operator, integrator | Generated: REST API, configuration, CLI, Helm values, authorization matrix |

Existing markdown is migrated **and rewritten** into task-oriented pages, not copied. Once a page
has moved, the repo copy is deleted and anything that linked to it links to the site.

### Generated reference pages

| Page | Source of truth | Generator |
| --- | --- | --- |
| REST API | `web/openapi.json` (already kept fresh by `openapi-check`) | `starlight-openapi` renders it at build time |
| Configuration | `env`/`envDefault` tags in `internal/config`, descriptions in `config.EnvDocs` | `cmd/docgen` |
| Authorization matrix | `authRules` (`api.AuthMatrixMarkdown`, as `cmd/authmatrix`) | `cmd/docgen` |
| CLI | `ocidex-cli` command tree | `ocidex-cli gen-reference` (hidden) |
| Helm values | `charts/*/values.yaml` and its comments | `cmd/docgen` (in-repo; helm-docs needs a comment convention the charts don't use) |

Each generated page carries a "generated, do not edit" comment and is checked by `docs-generate-check`.

Screenshots come from a Playwright script against the demo stack (`make demo`), at a fixed
viewport and theme, so visuals track the UI. They are regenerated on release, not on every PR.

### Versioning

The site at `/` documents the **latest release**. `main` publishes a preview at **`/next/`**,
built with `base: "/next/"` and a banner that it documents unreleased work. No per-minor archive
until 2.x exists; at that point the tag publish starts writing `/<major>.<minor>/` too.

### Publishing

* **PR pipeline:** a `docs-build` task, gated on changes under `site/` and the generators'
  sources, runs the site build (which includes the link check). The generated pages' staleness
  check runs in `codegen-check` (`make docs-generate-check`), which already has a Go toolchain.
* **Tag pipeline (`v*`):** `docs-publish` builds the site and replaces everything on `gh-pages`
  except `next/`.
* **Push pipeline (`main`):** `docs-publish` builds with the `/next/` base and replaces only
  `next/`.
* The publish step commits to `gh-pages` with the in-cluster `github-pipeline-token`, the same PAT
  `gh-release` uses to create releases (it already has `contents: write`). GitHub Pages serves the
  branch ("Deploy from a branch: gh-pages /"). The branch holds a `CNAME` with `docs.ocidex.app`
  and a `.nojekyll`.
* DNS: `docs.ocidex.app` is a CNAME to `pfenerty.github.io` in Cloudflare, **DNS only** (not
  proxied), so GitHub can issue the certificate.

### Consequences

* Good, because the site is static, so there is no service to run, and Pages is free and outside
  the homelab's blast radius: the docs stay up when the cluster is down.
* Good, because reference pages are generated and checked, so they can't drift from the code.
* Good, because one CI system: the docs tasks use the same tektonic patterns, images and token
  as the rest.
* Good, because docs ship in the same PR as the change they document.
* Bad, because publishing by pushing a branch is less atomic than `deploy-pages`. A force-push
  race between a tag run and a main run could drop one; the tag pipeline is rare and the next main
  push repairs `/next/`, so this is accepted.
* Bad, because the site is a second npm tree to keep current; Renovate covers it like `web/`.
* Bad, because two manual, one-time steps sit outside the repo: the Cloudflare CNAME and the
  repo's Pages setting.

### Confirmation

* `make docs-generate-check` (and `codegen-check` in CI) fails on a stale generated page, and
  `make docs-check` (and `docs-build`) fails on a broken internal link.
* `https://docs.ocidex.app` serves the latest release, and `/next/` serves `main`.
* `docs/` keeps only contributor material and ADRs once ocidex-mxy0.10 lands.

## Pros and Cons of the Options

### Astro Starlight

* Good, because Pagefind search, dark mode, MDX, i18n-ready nav and good accessibility come by
  default, and the output is plain static HTML with little JavaScript.
* Good, because it is TypeScript and Vite, which the team already runs for `web/`.
* Good, because plugins exist for what we need: `starlight-openapi`, `starlight-links-validator`.
* Bad, because it has no built-in versioning; the `/next/` split above is done in CI.

### Docusaurus

* Good, because versioning is built in.
* Bad, because it is React and ships a heavier client bundle, and versioning copies whole doc
  trees, which we don't need yet.

### MkDocs Material

* Good, because it is mature, with excellent search and admonitions.
* Bad, because it adds a Python toolchain to a Go/TS repo, and Material moved to maintenance mode
  in favour of Zensical, so its future is unsettled.

### VitePress

* Good, because it is light and Vite-based.
* Bad, because it is aimed at Vue projects, with fewer docs-site features (no OpenAPI plugin
  ecosystem to speak of, weaker IA defaults).

### Tekton pushes to `gh-pages`

* Good, because one CI system, and it reuses an existing token and existing images.
* Bad, because the commit-to-branch publish is less atomic than `deploy-pages`.

### GitHub Actions `deploy-pages`

* Good, because it is the native, OIDC-backed Pages flow with atomic deploys.
* Bad, because it introduces a second CI system with its own runners, conventions and supply-chain
  surface, for one job.

### Serve from the homelab cluster

* Good, because it is next to the app, behind the same gateway.
* Bad, because the docs would go down with the cluster, and it adds a deployment, a route and
  network policy to run for static files.

## More Information

* Epic ocidex-mxy0 and its children carry out this decision.
* [ADR-0052](0052-v1-compatibility.md): what counts as public API, which is what the reference
  section documents.
* The app serves its own API reference (ocidex-a0p4); the site renders the same `openapi.json`.
