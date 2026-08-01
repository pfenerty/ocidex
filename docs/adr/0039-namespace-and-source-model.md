---
status: "accepted"
date: 2026-08-01
decision-makers: Patrick Fenerty
---

# Namespace and source model

## Context and Problem Statement

OCIDex models the world as *registries → images → SBOMs*. That framing is in the schema, not just
the UI: `sbom.registry_id` is the ownership and visibility anchor for every read path, and
`registry` is the only table that can own anything.

The ingest pipeline itself is already type-agnostic. `resolveArtifact`
(`internal/service/sbom.go:86`) upserts `artifact` with whatever `metadata.component.type` the BOM
declares, and the container-specific rules — the digest requirement, `@sha256:` stripping,
`validateContainerRequired` — are correctly gated on `type == container`. `artifact.type` is a
real discriminator and `Artifacts.tsx` already offers an `application` filter.

What is missing is everything *around* that path. An SBOM for a Go binary, uploaded from CI, comes
from no registry. So it has no owner. And `sbom_visible()` (`00018`) treats that as *visible to
everyone*:

```sql
SELECT COALESCE(viewer_is_admin, false)
    OR reg_id IS NULL          -- ← every uploaded SBOM lands here
    OR EXISTS (SELECT 1 FROM registry WHERE id = reg_id AND ...)
```

`IngestSBOM` (`internal/api/sbom.go:15`) never sets `RegistryID`, so this is not hypothetical: the
upload path as it exists today is a read-visibility hole. Any non-container work has to answer
"who owns this?" before it can answer anything else.

The obvious minimal fix — let an SBOM point at a registry it did not come from — is a lie in the
schema, and the lie compounds. The concrete workflow that motivated this is the `ocidex` binary
(uploaded from CI) and `ghcr.io/pfenerty/ocidex` (scanned from GHCR). One project, one owner, two
ways in. Attributing the binary to the GHCR registry row would be false; giving it its own
registry row would split one project across two ownership boundaries on day one, and the
relationship queries this is all being built for would then have to join across them.

## Decision Drivers

* An uploaded SBOM must have an owner, and the default must be private rather than world-visible.
* Whatever we key visibility on must stay a *small* set. `00052_visible_registry_ids.sql` exists
  because per-row visibility on the rollup tables cost **121,080 calls / 3,818 ms / 242k buffer
  hits** to distinguish **eight** registries; the set-returning form drops the same scan node to
  **100 ms**. That is a load-bearing constraint on any redesign, not an optimisation detail.
* A binary and the image that ships it must be able to share an owner, so the relationship queries
  in ADR-041 are an ordinary join and not a cross-tenant one.
* Migration cost has to stay proportionate — this is a refactor of an anchor column touched by
  73 references across nine query files, on a live schema.
* Do not invent a new user-facing browse axis. Users currently see one flat "everything I can see"
  space and that is fine.

## Considered Options

* **Nullable owner on `sbom`** — keep the schema, add `sbom.owner_id`.
* **Ownership on `artifact`** — put `owner_id`/`visibility` where the thing being owned lives.
* **`source` supertype carrying ownership** — rename the concept: `source` owns, `registry`
  becomes its OCI subtype.
* **`namespace` / `source` / `registry`, three levels** — tenancy, ingest channel, and OCI config
  as separate tables.

## Decision Outcome

Chosen option: **`namespace` / `source` / `registry`**.

```
namespace (id, name, owner_id, visibility)     ← the authorization anchor
source    (id, namespace_id, kind, name)       ← the ingest channel
  registry (id → source.id, url, auth,
            patterns, trust config)            ← the oci_registry subtype

sbom      (namespace_id, source_id)
*_rollup  (namespace_id)                       ← honest: a visibility bucket
scan_jobs (registry_id)                        ← unchanged; truly registry-scoped
```

The decision rests on noticing that `registry`'s 26 columns are doing four unrelated jobs:

| Job | Columns | Lands on |
|---|---|---|
| Ownership / visibility | `name`, `owner_id`, `visibility` | `namespace` |
| Channel identity | (`name`, and the discriminator) | `source` |
| Discovery config | `type`, `url`, `insecure`, `webhook_secret`, `enabled`, `repository_patterns`, `tag_patterns`, `scan_mode`, `poll_interval_minutes`, `last_polled_at`, `repositories`, `auth_username`, `auth_token`, `include_untagged` | `registry` |
| Trust policy | `verification_mode`, `trust_public_key`, `trust_identity`, `trust_issuer` | `registry` |

Only the first job has anything to do with authorization, and it is the only one an uploaded SBOM
needs. Fusing it to the other three is what makes non-container artifacts impossible to own.

**The placement rule**, for anything added later: *ownership and visibility go on `namespace`; how
we found it goes on `source`; anything only meaningful when you can pull a manifest goes on
`registry`.*

Two findings say the rollup tables were already asking for this:

* **`registry_id` on the rollups is semantically a visibility bucket, not a registry.** That is
  precisely what `00052`'s comment describes it doing — evaluating the rule once per bucket and
  semi-joining. Renaming it `namespace_id` makes the column say what the code already means.
* **Registry is not a user-facing browse axis.** `Artifacts.tsx` and `Components.tsx` never filter
  by it, and `web/src/api/queries/registries.ts` is admin-only. So promoting a *new* concept to the
  ownership role costs no user-facing churn.

### Consequences

* Good, because an uploaded SBOM has a real owner. Today a NULL `registry_id` is world-visible by
  construction; after this, an SBOM with no resolvable namespace cannot be ingested at all.
  A namespace created implicitly for an upload source defaults to `private`. Note this is *not* a
  blanket default flip: the migration copies each registry's existing `visibility` verbatim, and
  `POST /api/v1/registries` keeps its current `public` default (`internal/api/registry.go`), so no
  existing data or client changes visibility. Only the previously-unowned case gets a new answer.
* Good, because the migration is cheap despite touching an anchor column. Ids are preserved: each
  existing registry yields **one namespace and one source that both reuse `registry.id`**. Every
  stored `registry_id` value remains valid as both `namespace_id` and `source_id`, so this is
  repointed foreign keys, not a data remap.
* Good, because `visible_namespace_ids` keeps `visible_registry_ids`' exact set-returning shape,
  so the `ocidex-ckv.2` performance work survives unchanged.
* Good, because a namespace can hold several sources, which is what makes ADR-041's `usages`
  query a plain join: the uploaded binary and the scanned image sit in one namespace.
* Good, because `scan_jobs` keeps keying on `registry_id`, untouched. Only OCI sources get
  scanned. If that column had *also* wanted to move, the subtype line would be drawn in the wrong
  place — it staying put is the check that it isn't.
* Bad, because it is three tables where there was one, and creating a registry becomes a
  three-row transaction. The API keeps `POST /api/v1/registries` as a single call that writes all
  three, so this cost is paid by the service layer rather than by every client.
* Bad, because `source.kind` (`oci_registry` | `upload`) sits next to the pre-existing
  `registry.type` (`zot` | `harbor` | `docker` | `generic`), and the two read like synonyms.
  They are not: `kind` is the subtype discriminator, `type` is an OCI-flavour hint used by the
  scanner. `type` stays on `registry` precisely because it is meaningless for an upload.
* Bad, because ~73 `registry_id` references across nine query files have to be repointed
  (`stats.sql` and `search.sql` are the bulk), and `registry.sql` splits three ways.
* Bad, because a shared namespace complicates operator ownership. See below.

**Operator ownership of a shared namespace.** `managed_by` / `managed_ref` (`00050`) mark a
registry whose config an external controller reconciles; `managed_ref` is already
`'<k8s-namespace>/<name>'` for an OCIRegistry CR. Those columns stay on `registry` and are
deliberately *not* copied to `namespace`, because two OCIRegistry CRs in one Kubernetes namespace
map to one OCIDex namespace — the namespace has no single managing CR. Consequently the operator
creates a namespace if absent but **never deletes one on CR deletion**; it deletes only the source
and registry rows it owns. A namespace outliving its last source is the correct outcome, not a
leak.

### Confirmation

* `make migrate-up` then `make migrate-down` clean on a seeded database — both directions, since
  this is reversible-or-nothing on an anchor column.
* Post-migration assertions in psql: no `sbom.namespace_id` is NULL, and per-namespace SBOM counts
  equal the pre-migration per-registry counts.
* `EXPLAIN ANALYZE` on the components list before and after. `visible_namespace_ids` must keep the
  semi-join shape; a regression here undoes `ocidex-ckv.2` and is the single most likely way to
  get this wrong quietly.
* `internal/api/auth_boundary_test.go` extended: a private namespace's SBOMs are invisible to a
  non-owner; ingest against a namespace you do not own is a 403; two sources in one namespace
  share visibility.
* An OCIRegistry CR in Kubernetes namespace `foo` lands in OCIDex namespace `foo` by default;
  deleting it leaves the namespace standing.

## Pros and Cons of the Options

### Nullable owner on `sbom`

* Good, because it is the smallest possible change and closes the visibility hole immediately.
* Bad, because ownership then lives on individual SBOM rows, so the rollup tables have nothing
  low-cardinality to bucket on — this is the `00052` failure mode, reintroduced deliberately.
* Bad, because nothing groups a binary with the image that ships it, so ADR-041's queries have no
  scope to run within.

### Ownership on `artifact`

* Good, because it is the most honest model of the domain: the artifact is the thing being owned.
* Bad, because per-artifact visibility destroys the cheap `IN (SELECT visible_…_ids)` semi-join.
  With thousands of artifacts rather than eight registries, the planner is back to evaluating the
  rule per rollup row — the exact problem `00052` was written to fix. This is the k.o. criterion.
* Bad, because it gives no home to the channel config, so `registry` keeps its other three jobs
  anyway and we end up with ownership split across two places.

### `source` supertype carrying ownership

* Good, because it is one fewer table, and it does correctly separate "how we found it" from
  "what it is".
* Bad, because it leaves tenancy fused to the ingest channel — it renames the problem rather than
  decomposing it. The binary-plus-image workflow still straddles two owners, which is the specific
  thing that has to work.
* Bad, because the rollup column would become `source_id`, which is *less* honest than
  `registry_id`: rollups have never cared how an SBOM arrived, only who may see it.

### `namespace` / `source` / `registry`

* Good, because each table has exactly one job, and the rollup column finally names what it does.
* Good, because it is the only option where one owner can hold several channels.
* Bad, because it is the most tables and the most migration surface (see Consequences).

## More Information

**Naming: the Kubernetes collision.** All three CRDs are `scope=Namespaced`
(`api/v1alpha1/{ociregistry,apikey,scanrequest}_types.go`), so OCIDex `namespace` now collides
with `metadata.namespace` inside `internal/controller/`. `project` was considered and rejected as
vaguer about the authorization role.

The collision is turned into a mapping rather than merely tolerated: **an OCIRegistry's OCIDex
namespace defaults to its Kubernetes namespace.** The two concepts line up — both are "the
tenancy boundary this object belongs to" — so the defaulting rule is one a reader can guess. It
also costs nothing to implement, because `managed_ref` already stores `'<k8s-namespace>/<name>'`.

Controller code keeps the two visibly distinct: `service.Namespace` versus
`client.ObjectKey.Namespace`, and never a bare `ns` variable in a file where both are in scope.

**Relationship to ADR-025.** ADR-025 chose "a simple ownership model over a full RBAC system;
complexity would be added only if multi-tenancy requirements grew beyond single-owner registries."
This is that condition arriving: the owned thing is now a namespace that may hold several
channels. ADR-025 is **amended, not superseded** — its roles table, its `public`/`private`
semantics and its API-key scope rules (`read` / `write`, `isWriteAllowed`) all carry over
verbatim. The single change is the noun: "Registry Owner" becomes "Namespace Owner", and
`canManageRegistry` (`internal/api/registry.go:518`) resolves ownership through the namespace
rather than reading `reg.OwnerID` directly. Nothing about *what* a role may do changes.

Related: ADR-024 (outbox pattern; `scan_jobs` is unaffected), ADR-030 (operator CRDs), ADR-040
(non-container artifact identity, which depends on this), ADR-041 (derived artifact
relationships, which depends on this).
