---
status: "accepted"
date: 2026-08-09
decision-makers: Patrick Fenerty
---

# Canonical resource URLs

## Context and Problem Statement

Every resource detail route in OCIDex addresses its subject by internal UUID: `/artifacts/{id}`,
`/sboms/{id}`, `/components/{id}`, `/licenses/{id}/components`. A UUID is unguessable, so a URL can
only be obtained by first navigating the UI or querying the list API. Nobody outside the
application can construct one.

That makes external linking impossible in exactly the places it would be most useful. A runbook
cannot say "see `ocidex/artifacts?name=ghcr.io/pfenerty/ocidex`". A CI job that just pushed
`v1.2.3` cannot annotate the build with a link to the SBOM it produced, because it knows the image
name and tag but not the UUID that ingest assigned. A Slack message about `CVE-2021-23337` cannot
link to the vulnerability page.

Should a human-composable URL scheme keyed on `name` and `version` replace the UUID scheme,
supplement it, and for which resources?

## Decision Drivers

* Externally composable links are the whole point. A scheme that still requires a round trip to
  discover an identifier has not solved anything.
* Names in this domain contain URL-structural characters. Artifact names are full repository
  paths and purls carry `/`, `@`, and `:`. Any scheme that cannot survive them is not viable.
* Not every resource has a name that identifies it. Where the underlying table has no natural key,
  a name-keyed URL would be ambiguous by construction, and inventing one would be worse than
  keeping the UUID.
* Ambiguity must never leak visibility. Artifacts are global rows with many-to-many namespace
  visibility (ADR-039); "your query matched 3 things" must not be how a caller learns that a
  private artifact exists.
* UUID URLs already work and are wired into ~19 frontend link-construction sites, `pkg/client`,
  and the generated `web/openapi.json` / `web/src/types/openapi.d.ts`. Breaking them buys nothing.

## Considered Options

* Replace UUID paths with name-keyed paths, e.g. `/artifacts/by-name/{name}`
* Replace UUID URLs with name-keyed query URLs as the address-bar form
* Additive name-keyed resolver endpoints alongside unchanged UUID paths

## Decision Outcome

Chosen option: **additive name-keyed resolver endpoints, keyed by query parameter**, because it is
the only option that delivers composable links without either breaking existing URLs or being
defeated by slashes in names.

The rules below are normative.

### Rule R1 — Query parameters, never path segments

Name-keyed lookups take their key in the **query string**, not in a path segment.

This is not a stylistic preference. `resolveArtifact` (`internal/service/sbom.go:137`) stores
container artifact names as the full repository path — `docker.io/ubuntu`,
`ghcr.io/pfenerty/ocidex` — as `TestResolveArtifact_ContainerDigestInName`
(`internal/service/sbom_ingest_test.go:328`) fixes. Purls are worse: `pkg:golang/github.com/pfenerty/ocidex@v1.2.3`
carries `/`, `@`, and `:`.

A `{name}` path segment cannot carry those. Percent-encoding `/` as `%2F` does not rescue it: chi
decodes before routing, and the nginx layer adopted in ADR-038 normalizes encoded slashes. A query
string has no such problem — `/` is legal unencoded in a query value.

**Corollary:** the existing `GET /api/v1/registries/by-name/{name}` (`internal/api/router.go:512`)
and `GET /api/v1/namespaces/by-name/{name}` (`internal/api/router.go:584`) are **not** deprecated
by this ADR. Registry and namespace names are slash-free and globally unique
(`registry_name_key`, `namespace.name … UNIQUE`), so the path form is legitimate there. Do not
generalize that pattern to artifacts, SBOMs, or components.

### Rule R2 — UUID paths remain canonical

Existing `/{id}` routes keep their UUIDs, keep `format:"uuid"` on the path param, and remain the
form every internal link emits. Resolvers are **new** endpoints that return the resource; they do
not change, redirect, or alias the existing ones. Nothing needs migrating, and no existing link
breaks.

### Rule R3 — Applicability is decided by the table, not by taste

A resource gets a name-keyed resolver only when its identity is expressible from user-known
values. Verdict per resource:

| Resource | DB identity | Resolver |
|---|---|---|
| `artifact` | `UNIQUE (type, name, COALESCE(group_name,''))` — `db/migrations/00002_artifact.sql` | **Yes**, on `name` with `type` / `group` as qualifiers |
| `sbom` | `UNIQUE (digest)`; `(artifact_id, subject_version)` is **not** unique | **Yes**, on `artifact`+`version` with `arch` / `flavor` as qualifiers, plus a `digest` form |
| `license` | `UNIQUE(spdx_id) WHERE NOT NULL`; `UNIQUE(name) WHERE spdx_id IS NULL` | **Yes**, on `spdxId` |
| `vulnerability` | `id TEXT PRIMARY KEY` = `CVE-…` / `GHSA-…` | **Already canonical**, no work |
| `component` | per-SBOM row (`component.sbom_id` FK) | **No** — see R6 |

Vulnerabilities are already done. `internal/api/types.go:580` declares the path param as a plain
string with no `format:"uuid"`, so `/api/v1/vulns/CVE-2021-23337` and `/vulnerabilities/CVE-2021-23337`
resolve today. Any statement to the contrary is stale.

An SBOM's `digest` is unique by construction (`idx_sbom_digest`, `db/migrations/00006_sbom_digest_unique.sql`),
so `?digest=` is a lookup rather than a search and can never be ambiguous.

### Rule R4 — The qualifier ladder

`name` alone is not a key for artifacts or SBOMs. Callers narrow with qualifiers, in this order:

* **artifact**: `name` → `+type` → `+group`. The full triple is exactly the unique index.
* **sbom**: `artifact`+`version` → `+arch` → `+flavor`. One version fans out across architecture
  and flavor variants; `ArtifactVersion.SBOMCount` and `.Architectures`
  (`internal/service/search.go:304`) are the evidence that the fan-out is real.

Omitted qualifiers are wildcards, not empty-string matches. Supplying every qualifier for a
resource reduces its lookup to the unique index and cannot be ambiguous.

### Rule R5 — Ambiguity resolution and visibility ordering

A resolver returns:

* **200** with the resource when exactly one *visible* candidate matches;
* **404** when zero visible candidates match;
* **409 Conflict** with the candidate list when more than one visible candidate matches. The body
  carries each candidate's canonical id plus the qualifier values that distinguish it, so the
  caller can retry one rung further down the R4 ladder.

`409` is chosen over `300 Multiple Choices` because huma models it as a typed error body that
survives into the generated TypeScript client; `300` does not.

**Visibility is applied before the count, not after.** Candidates are filtered through
`artifact_visible(a_id, viewer_id, viewer_is_admin)` / `visible_namespace_ids(viewer_id, viewer_is_admin)`
(`db/migrations/00053_namespace_source.sql`) and only then counted. Filtering after counting would
let a private artifact turn a unique public match into a reported ambiguity, which is a
visibility leak.

A candidate the caller cannot see is **404, not 403** — matching the behaviour `GetRegistryByName`
(`internal/api/registry.go:199`) and `GetNamespaceByName` (`internal/api/namespace.go:78`)
already implement, where a private resource collapses to a not-found rather than admitting it
exists.

### Rule R6 — `component` is out of scope

A `component` row is scoped to one SBOM (`component.sbom_id`, `db/migrations/00001_initial_schema.sql`).
The same package appears as a distinct row in every SBOM that contains it, so there is no
`name`+`version` that identifies *a* component. A name-keyed component detail route would have to
pick an arbitrary row.

The cross-SBOM concept users actually mean is purl-keyed, and it is already served by
`/api/v1/components/distinct` (`internal/api/router.go:256`) and `/api/v1/components/versions`
(`internal/api/router.go:272`). The right shape for components is therefore a **list filter**,
`/components?purl=`, not a detail resolver. `/components/{id}` keeps its UUID.

### Rule R7 — Endpoint and route shapes

```
GET /api/v1/artifacts/lookup?name=ghcr.io/pfenerty/ocidex&type=container&group=
GET /api/v1/sboms/lookup?artifact=ghcr.io/pfenerty/ocidex&version=1.2.3&arch=amd64&flavor=wolfi
GET /api/v1/sboms/lookup?digest=sha256:…
GET /api/v1/licenses/lookup?spdxId=Apache-2.0

WEB /artifacts/lookup?name=…              → resolve → replace-navigate → /artifacts/<uuid>
WEB /sboms/lookup?artifact=…&version=…    → resolve → replace-navigate → /sboms/<uuid>
```

`lookup` is a literal path segment and therefore cannot collide with a UUID param. The web routes
resolve client-side and `navigate(…, { replace: true })` to the canonical UUID route, so the back
button does not trap the user on the resolver. On a `409` the route renders a disambiguation list
instead of navigating.

### Consequences

* Good, because a link becomes constructible from facts a CI job or a human already has — an image
  name and a tag — with no prior API call.
* Good, because nothing migrates. Every existing UUID URL, every frontend link site, `pkg/client`,
  and the generated OpenAPI types are untouched.
* Good, because ambiguity is a first-class, actionable response rather than a silent
  pick-the-first, and the qualifier ladder tells the caller exactly how to disambiguate.
* Bad, because after resolution the address bar shows the UUID, so a user who copies the URL from
  the address bar copies the non-shareable form. The compensating change is a **"Copy shareable
  link"** affordance on the artifact and SBOM detail pages that emits the resolver URL; it is
  filed as part of the implementation epic, not optional polish.
* Bad, because the resolver endpoints duplicate filter logic that the list endpoints already have.
  Accepted: a resolver's contract (unique-or-409) is genuinely different from a list's
  (zero-or-more), and collapsing them would make the list endpoints lie about cardinality.
* Neutral: two lookup styles now coexist — `by-name/{name}` for registries and namespaces,
  `?…` resolvers for artifacts and SBOMs. R1's corollary records why, so the inconsistency is a
  documented consequence of the data rather than drift.

### Confirmation

* Each resolver has table-driven handler tests covering the 200 / 404 / 409 outcomes, alongside
  the existing `internal/api/registry_test.go` pattern.
* A visibility test asserts that a private candidate does **not** convert a unique public match
  into a `409`, and that a lookup matching only invisible candidates returns `404` rather than
  `403`.
* An artifact-name test uses a slash-bearing name (`ghcr.io/pfenerty/ocidex`) end to end, so a
  future move back to path segments fails the suite rather than shipping.
* `make openapi` regenerates `web/openapi.json` and `web/src/types/openapi.d.ts`; the frontend
  build enforces the resolver response types.

## Pros and Cons of Options

### Replace UUID paths with `/artifacts/by-name/{name}`

* Good, because it is the pattern already in the codebase for registries and namespaces, so it
  needs no new concepts.
* Bad, because it is defeated by the data. Container artifact names contain slashes; encoded
  slashes are decoded by chi before routing and normalized by nginx (ADR-038).
* Bad, because artifact names are not unique on their own, so the route would need `type` and
  `group` as additional segments, producing a URL nobody can compose from memory anyway.

### Replace UUID URLs with name-keyed query URLs as the address-bar form

* Good, because the URL a user copies from the address bar is always shareable, with no extra
  affordance needed.
* Bad, because it rebuilds ~19 frontend link-construction sites (`web/src/pages/**`,
  `web/src/components/**`), converts every detail page to load-by-name, and turns UUID routes into
  redirects, for a benefit a copy-link button delivers at a fraction of the cost.
* Bad, because it forces the ambiguity case into the primary navigation path: every detail page
  load becomes a potential disambiguation screen.

### Additive name-keyed resolver endpoints (chosen)

* Good, because it is purely additive — no existing URL, client, or generated type changes.
* Good, because the resolver contract is explicit about ambiguity, which the UUID path can never
  encounter and a list endpoint would paper over.
* Bad, because the shareable URL is not the one in the address bar without a copy-link affordance.

## More Information

* Spike issue: `ocidex-e86`. Implementation epic: `ocidex-ri2p`.
* ADR-039 (namespace and source model) defines `artifact_visible()` and `visible_namespace_ids()`,
  which R5 depends on.
* ADR-040 (non-container artifact identity) establishes caller-declared `type`/`name`/`group`,
  which is what makes the R4 artifact ladder expressible by the caller.
* ADR-038 (web serving and base image policy) is why encoded slashes cannot be relied on.
