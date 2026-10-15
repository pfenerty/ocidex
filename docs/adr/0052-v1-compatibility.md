---
status: "accepted"
date: 2026-10-15
decision-makers: Patrick Fenerty
---

# 1.0 scope and compatibility guarantees

## Context and Problem Statement

OCIDex is heading for a 1.0 release under semantic versioning. Semver is only meaningful once
the project says *what* the version number covers. Today it covers nothing in particular. The
OpenAPI `info.version` is hard-coded to `1.0.0`. The Go SDK (`pkg/client`) is versioned with
the whole server module. Operator CRDs are `v1alpha1`. `cmd/` holds 18 binaries, several of
them one-shot maintenance tools. Tags `v0.0.1` and `v0.0.2` were cut without
`scripts/release.sh`, so nothing checked them against the changelog.

Which interfaces does a 1.0 release promise not to break inside a major version, and which
are explicitly excluded?

## Decision Drivers

* An operator must be able to take any 1.x upgrade without reading code.
* Every promise must be enforceable by CI or by a release checklist. A promise nothing
  checks will be broken by accident.
* A small surface is cheap to keep and can grow later. A large surface cannot shrink before
  2.0.
* Integrators (the CLI, the MCP server, the k8s-agent, CI pipelines that POST SBOMs) all
  reach OCIDex through `/api/v1` or the Go SDK.

## Considered Options

* **Narrow public contract, explicit exclusions** (each interface below listed as in or
  out).
* **Everything shipped is covered** (every binary, chart and CRD is semver-stable at 1.0).
* **HTTP API only** (only `/api/v1` is covered and everything else is best-effort).

## Decision Outcome

Chosen option: "Narrow public contract, explicit exclusions". "Everything shipped" would
freeze alpha CRDs and internal tools that are still changing. "HTTP API only" leaves
operators with no promise about the env vars and Helm values they actually touch on an
upgrade.

A **breaking change** to an in-scope interface requires a new major version. Before removal,
anything deprecated stays for at least **one minor release** and is announced in
`CHANGELOG.md` and `docs/UPGRADING.md`.

### In scope (stable for 1.x)

| Interface | What is covered | What is not |
|---|---|---|
| **HTTP API `/api/v1`** | Paths, methods, request and response schemas, status codes, auth schemes, as defined in `docs/API_VERSIONING.md`. Breaking-change definition there is confirmed and is checked by `oasdiff` against the last release tag (ocidex-tkn9.3). | Undocumented endpoints, error message *text*, ordering not specified by the pagination convention (ADR-043), `/metrics` series names, timing. |
| **Go SDK `pkg/client`** | Exported identifiers. The SDK becomes its own module `github.com/pfenerty/ocidex/pkg/client`, tagged `pkg/client/vX.Y.Z`, so consumers do not inherit the server's dependency graph (ocidex-tkn9.4). Its major tracks the HTTP API major. | Generated internals marked as such. |
| **CLI `ocidex-cli`** | Command paths, flag names and meaning, exit codes, and `-o json` / `-o yaml` output shapes (ADR-029). | `-o table` output, which is for humans and may change in any release. |
| **MCP server `ocidex-mcp`** | Tool names and input schemas (ADR-045). | Tool description text and the prose of tool results. |
| **Configuration** | Environment variables in `docs/CONFIGURATION.md`, and the values of `charts/ocidex`. Removing or renaming one, or changing its default in a way that changes behavior, is breaking. A deprecated name keeps working, logging a warning, for at least one minor release. | Values marked internal or experimental in the chart's comments. |
| **Ingestion format** | CycloneDX JSON (spec versions accepted at 1.0). | SPDX and CycloneDX XML are **out of scope for 1.0**. Adding them later is an additive, minor change. |
| **Release artifacts** | Image names under `ghcr.io/pfenerty/ocidex*`, chart names, cosign signatures and attached SBOMs as described in `docs/verifying-artifacts.md`. | Image digests, base image choice (ADR-038). |

### Explicitly excluded

* **Database schema.** It is not an API. Read it, and you may break on any release.
  Integrations go through `/api/v1`.
* **Operator (`cmd/operator`, CRDs `api/v1alpha1`, `charts/ocidex-operator`).** These stay
  alpha. They are released and supported (bugs are fixed), but they carry no compatibility
  promise until they are promoted to `v1beta1` or later by a separate ADR.
* **k8s-agent (`cmd/k8s-agent`, `charts/ocidex-k8s-agent`).** It ships and is supported on
  the same alpha terms as the operator (ADR-044). Its wire contract with the server is
  `/api/v1`, which *is* covered.
* **NATS subjects, stream names and message payloads.** These are internal to one
  deployment. All workers are upgraded with the server.
* **Go packages under `internal/`**, and the root module's import path as a library.

### Binaries

| Supported (released, documented, covered where listed above) | Internal (not released as a supported interface) |
|---|---|
| `ocidex`, `scanner-worker`, `oci-metadata-worker`, `git-worker`, `user-enricher-worker`, `provenance-worker`, `vuln-worker`, `ocidex-cli`, `ocidex-mcp`, `operator` (alpha), `k8s-agent` (alpha) | `authmatrix`, `specgen` (build tooling), `dbcheck`, `mock-idp` (test rig), `vuln-parity` (ADR-049 migration aid), `backfill-*` (one-shot maintenance; retired before 1.0 by ocidex-bt62.1) |

Server and worker binaries are only supported at the **same version**. Mixed-version
deployments are not a supported state outside a rolling upgrade.

### Upgrade policy

* **Into 1.0:** only from the latest 0.x minor release. Earlier 0.x upgrade to it first.
* **Within 1.x:** directly from any 1.x to any later 1.x. No intermediate stops.
* **Migrations are forward-only as a supported path.** Every migration has a `Down` step
  for development, but several are lossy (00069, 00070). Down migrations are not a
  supported rollback. The supported rollback is restoring the pre-upgrade database backup
  and redeploying the previous version. `docs/UPGRADING.md` makes the backup a required step.
* Migrations run before the new version serves traffic (the `migrate` subcommand or the
  chart's migrate Job), and a failed migration leaves the old version serving.

### Supported platforms

Support means "tested in CI or the release checklist". Dropping a version that its upstream
has end-of-lifed is allowed in a minor release, with a note in `docs/UPGRADING.md`.

* **PostgreSQL:** major versions exercised by the integration tests (18 at the time of
  writing).
* **NATS:** 2.x with JetStream enabled.
* **Kubernetes** (for the charts): the minor versions still inside upstream's support
  window.

### API and build versions

The OpenAPI `info.version` is the **API contract version**. It is a constant in
`internal/api` that is bumped on purpose: the minor on additive changes and the major
together with a new `/api/vN` prefix. It is never the build version, so specgen output
stays deterministic. The running server reports its build version separately
(ocidex-tkn9.2).

### Consequences

* Good, because every promise has an enforcement point: oasdiff for the API, the SDK's own
  module and tests, `make openapi-check`, and `docs/UPGRADING.md` in the release checklist.
* Good, because the operator and k8s-agent can keep changing their CRDs and values without a
  2.0.
* Bad, because config env vars and chart values are now frozen surface. Every rename costs a
  deprecation cycle.
* Bad, because a separate SDK module adds a second tag scheme and a `go.work` or `replace`
  for local development.

### Confirmation

* ocidex-tkn9.3 fails PRs that break `/api/v1` against the last release tag.
* ocidex-tkn9.4 makes `cd pkg/client && go test ./...` pass in isolation.
* ocidex-tkn9.6 (`docs/UPGRADING.md`) and ocidex-tkn9.7 (`docs/RELEASING.md`) make the
  upgrade policy and the deprecation notes part of every release.

## Pros and Cons of the Options

### Everything shipped is covered

* Good, because it is simple to state.
* Bad, because it freezes `v1alpha1` CRDs and one-shot tools, or forces 2.0 for routine
  changes to them.

### HTTP API only

* Good, because it is the one surface already checked by CI.
* Bad, because operators' real upgrade risk is in env vars, chart values and migrations,
  and it says nothing about them.
* Bad, because SDK consumers get no promise even though the SDK is the API's main client.

## More Information

* `docs/API_VERSIONING.md` holds the breaking-change definition for the HTTP API.
* ADR-029 (CLI), ADR-043 (pagination), ADR-044 (k8s-agent), ADR-045 (MCP).
