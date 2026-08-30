---
status: "accepted"
date: 2026-08-30
decision-makers: Patrick Fenerty
---

# Namespace membership with compile-time capabilities

## Context and Problem Statement

A namespace had exactly one nullable `owner_id`, and every authorization question reduced
to "are you that user, or an installation admin". That is enough for one person per
project and nothing else. It cannot express the arrangement every real team has: five
people share a namespace, the security engineer among them may re-run a scan to confirm a
fix but must not be able to walk off with the registry credential, and CI may publish
SBOMs but must not be able to delete one.

The binary model also leaked into places it did not belong. ADR-044 K8's cluster
inventory push had no capability of its own, so it reused the API key's `read-write`
scope: a key issued to a build pipeline for uploading SBOMs could also replace the
workload inventory of any cluster its owner had. There was no narrower thing to ask for.

ADR-025 chose the simple ownership model deliberately and said so — its Consequences
section predicted this exact migration ("upgrading to a full RBAC model later would
require a new roles table"). ADR-039 then moved the anchor from registry to namespace,
which left ADR-025 describing a `RequireRegistryOwner` middleware and a registry `public`
boolean that no longer exist. This ADR supersedes it.

## Decision Drivers

* **The unit of sharing must be the thing people already name.** Whatever holds the
  member list has to be the thing a person points at when they say "give her access to
  that", or the model acquires a level of indirection that every query and every screen
  then has to explain.
* **Authorization must be enumerable at build time.** `docs/AUTH_MATRIX.md` is generated
  from the operation table and checked in CI. It is a control, not documentation, and it
  stops being one the moment the answer depends on a row someone can edit.
* **One copy of the rule.** The operation-level half (may you call this at all) runs in
  middleware; the row-level half (which rows come back) runs in SQL. Two copies of an
  authorization table that are free to drift is the shape of a privilege bug that no test
  on either side can see.
* **A credential must be narrowable below its holder.** A key handed to a build pipeline
  should be able to do less than the human who minted it, and it should not be possible
  to widen it back by changing the key.
* **Revocation must not require finding the credential.** Removing someone's access has
  to take effect on keys they minted months ago, without anyone having to enumerate them.

## Considered Options

* Membership on the namespace, with compile-time roles and capabilities
* A team/organisation entity above namespace, with namespaces belonging to a team
* Teams plus per-namespace overrides
* Database-defined roles with an editable capability table

## Decision Outcome

Chosen option: **membership on the namespace, with compile-time roles and capabilities**.
The namespace is already the authorization anchor (ADR-039), the thing a user names, and
the thing a cluster, source, and artifact all hang off. Making it the team costs no new
concept and no second tenancy level in every query. A team entity buys grouping that
nobody has asked for yet, at the price of a join in every visibility path; it can be
added later above this model without invalidating it.

### Rule M1 — Membership attaches to the namespace, and replaces ownership

`namespace_member (namespace_id, user_id, role)` (migration 00065), primary key on the
pair. `namespace.owner_id` is gone (00067); where the API still reports an owner it is
derived by the `namespace_owner(ns_id)` SQL function reading the owner row.

Exactly one owner per namespace is a database invariant, not a service convention:

```sql
CREATE UNIQUE INDEX namespace_one_owner
    ON namespace_member (namespace_id) WHERE role = 'owner';
```

The index is **partial**, which is the detail every caller has to know: it permits *zero*
owners, so it catches a concurrent attempt to create a second owner but says nothing
about demoting the last one. Member management therefore reads the current owner
explicitly before a demote, and relies on the unique violation only for the
second-owner race.

### Rule M2 — Five roles, ten capabilities, and the matrix is code

Roles are closed and mirror the `CHECK` on `namespace_member.role`:
`owner`, `maintainer`, `security`, `developer`, `viewer`.

Capabilities are the unit authorization is expressed in. An operation declares the
capability it needs; a role either grants it or does not. Roles never appear in an
operation's declaration, so adding a role cannot silently widen an existing endpoint.

| Capability | owner | maintainer | security | developer | viewer |
|---|:--:|:--:|:--:|:--:|:--:|
| `read_private` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ingest` | ✓ | ✓ | | ✓ | |
| `trigger_scan` | ✓ | ✓ | ✓ | ✓ | |
| `push_inventory` | ✓ | ✓ | | ✓ | |
| `delete_artifact` | ✓ | ✓ | | | |
| `manage_source` | ✓ | ✓ | | | |
| `manage_cluster` | ✓ | ✓ | | | |
| `read_secret` | ✓ | ✓ | | | |
| `manage_member` | ✓ | | | | |
| `delete_namespace` | ✓ | | | | |

Two splits in that table are the whole reason five roles exist rather than three:

* **`trigger_scan` without `ingest`** is what makes `security` a useful role.
  Re-running a scan creates no new content and reveals nothing a reader cannot already
  see, so confirming that a fix landed must not require the right to publish.
* **`read_secret` at maintainer, not security.** A security member reads everything the
  namespace knows; they do not get to read the registry password back out. That single
  capability is the entire difference between the two roles, and it is the one that would
  have been quietly granted by any "read everything" role.

`developer` is deliberately shaped like CI rather than like a person: read, ingest, push
inventory, re-scan, and nothing that reconfigures anything.

### Rule M3 — Capabilities are compile-time, not database-defined

`internal/authz` holds `roleCaps`, a `map[Role]map[Capability]bool` in which every role
names every capability explicitly — including the ones it does not hold, so a `false` is
a decision somebody made rather than an entry somebody forgot. The map is unexported;
callers ask `Role.Allows`, `authz.Allow`, or `authz.RolesWith`. Nobody reads the table
and reimplements the lookup, which is how the two halves of an authorization model drift
apart.

This is the option that was hardest to give up, because DB-defined roles are what a
mature product eventually wants. The reason to refuse it here is the second driver: the
conformance harness enumerates the matrix at build time and probes every capability
operation from both sides. That is what makes `docs/AUTH_MATRIX.md` a control rather than
a description. A role whose capabilities live in a table can be edited into a shape no
test ever saw, and the generated matrix becomes a snapshot of one row set rather than a
statement about the system. A new role is a code change because a role without a
capability set grants nothing.

`internal/authz` imports neither `internal/api` nor `internal/service`
(`TestPackageHasNoInternalImports`). The operation-level half needs it in the API layer
and the row-level half needs it in the service layer; a model that lived in
`internal/api` would force the service layer to import upward or keep a second copy.

### Rule M4 — The row-level rule stays in SQL functions, and callers must not inline it

Visibility is three functions — `visible_namespace_ids`, `sbom_visible`,
`artifact_visible` — rewritten in 00066 to consult `namespace_member` instead of
`owner_id`, plus `owned_namespace_ids` for the "mine" set and
`namespace_ids_with_capability` for row-level capability filtering.

The set-returning shape is not a stylistic choice. 00052 recorded the measurement: the
per-row `EXISTS` form cost 121,080 calls and 3,818 ms on a rollup read path to
distinguish eight registries; the set-returning form evaluates the rule once per
namespace and semi-joins, and the same scan node drops to 100 ms. Both forms exist and
their disjuncts are identical by construction, so they agree — but a caller that inlines
the disjuncts into its own `WHERE` gets neither guarantee, and a fourth copy of the rule
that no migration will ever update.

`namespace_ids_with_capability(viewer_id, viewer_is_admin, capable_roles TEXT[])` takes
**roles, not a capability name**, which is a deliberate departure from the obvious
signature. Passing a capability would require a capability→roles table in SQL: a second
copy of `roleCaps`, free to drift. Callers pass `authz.RolesWith(cap)`, the one place in
the system that resolves a capability to roles. The function has no public disjunct —
public means readable, not writable.

### Rule M5 — An API key carries capabilities, and they are a ceiling

`api_key.scope` (`read` / `read-write`) is replaced by `api_key.capabilities TEXT[]`
(migration 00068), constrained to the ten known names.

The list is a **ceiling, not a grant**. What a key may actually do is the declared
capabilities **intersected with its holder's live namespace roles**, evaluated on every
request. Three things follow, and all three are the point:

* Narrowing a member's role narrows every key they hold, immediately, with no key change
  and without anyone enumerating their keys.
* A key can be issued weaker than its holder — the ADR-044 K8 gap, closed: a key
  declaring only `ingest` is refused `push_inventory`, so the pipeline that uploads SBOMs
  can no longer replace a cluster's inventory.
* A key can never be issued *stronger* than its holder, so minting one is not a privilege
  escalation and needs no separate authorization.

An empty capability list on the create request means "every capability", which under the
intersection resolves to exactly "whatever I may do" — the historical `read-write`
behaviour, and a key that keeps tracking its owner rather than freezing against a later
promotion. The `read-write` backfill is therefore all ten, not the owner's grant set
frozen at migration time: identical on day one, and correct afterwards.

The intersection is applied in `can()` in `internal/api/authz.go`, **before**
`authz.Allow` and deliberately outside it. `Allow` short-circuits an installation admin,
and an admin who issued themselves a key scoped to `{ingest}` must not have that key
answer for `delete_namespace`. A capability the credential does not carry is a deny that
no membership — and no global role — restores.

`RequireWrite` survives unchanged in meaning as a coarse gate, now asking only whether
the key carries any mutating capability. The per-operation capability is what narrows an
individual endpoint; keeping `RequireWrite` coarse is what let the ~40 operations
declaring `Write` go untouched.

A capability string the running build does not recognise is **dropped** when a key is
validated, never honoured and never fatal. It can only come from a build that knew a
capability this one does not, and a key must narrow, never fail open, across a downgrade.

### Rule M6 — The global role is a separate axis

`ocidex_user.role` (`admin` / `member` / `viewer`) decides whether you may use the
installation at all; the namespace role decides what you may do inside a namespace you
belong to. `authz.Allow(globalRole, memberRole, present, cap)` is the single place the
two axes meet: an admin short-circuits, a global `viewer` is refused every mutating
capability regardless of membership, and everyone else is answered by their membership.

### Consequences

* Good, because sharing a namespace is now expressible, and the arrangement most teams
  actually have — a security reader who cannot publish or read credentials — is a role
  rather than a compromise.
* Good, because revoking access is one row. It reaches sessions and every API key the
  member holds, without finding the keys.
* Good, because `docs/AUTH_MATRIX.md` remains generated and enforced: the capability
  column is now the substantive one, and every capability operation is probed from both
  the granted and the denied side.
* Good, because the ADR-044 K8 authorization note is no longer a stated compromise.
* Bad, because a new role or capability is a deploy, not a configuration change. This is
  the price of the build-time matrix and is paid knowingly.
* Bad, because "one owner per namespace" is enforced by a partial index that tolerates
  zero owners, so the demote-the-last-owner case needs an explicit read and cannot be
  left to the constraint. Every future caller that changes a role has to know this.
* Bad, because there is still no grouping above namespace. An organisation with thirty
  namespaces manages thirty member lists. A team entity remains addable later.
* Neutral, because `api_key.scope` is gone rather than deprecated. The pair had two
  values and both map exactly onto capability sets, so nothing needed a grace period —
  but the `APIKey` CRD's `spec.scope` and `ocidex-cli`'s `--scope` are breaking renames
  to `spec.capabilities` and `--capability`.

### Confirmation

* `TestEveryRoleDeclaresEveryCapability` fails the build on a role or capability added
  without an explicit answer in every cell; `TestCapabilityMatrix` asserts the table
  above.
* `TestRolesWithMatchesTheTable` and `TestDominatesAgreesWithTheTable` keep the two
  derived views of `roleCaps` honest.
* `TestPackageHasNoInternalImports` keeps `internal/authz` importable by both layers.
* `TestAuthClassCoverage` fails if a registered operation declares no class, or one
  contradicted by the router's middleware wiring; `TestPersonaConformance`,
  `TestEveryEnforcedCapabilityIsProbedBothWays`, and
  `TestCapProbesCoverEveryCapabilityOperation` exercise every capability operation from
  both sides against real personas.
* `TestCapabilityHasOneConstructor` bans `authz.Allow(` outside `internal/api/authz.go`,
  and `TestVisibilityFilterHasOneConstructor` does the same for the row-level filter, so
  the key ceiling cannot be bypassed by a second call site.
* `TestNoOwnerIDInQueries` fails on a query that reaches for the retired column.
* `make auth-matrix-check` regenerates `docs/AUTH_MATRIX.md` and fails CI if it differs.

## Pros and Cons of the Options

### Membership on the namespace, with compile-time roles and capabilities

* Good, because it adds no new entity: the thing people already name is the thing that
  holds the member list.
* Good, because the whole matrix is enumerable at build time, which is what the
  conformance harness and the generated matrix depend on.
* Bad, because changing a role's powers requires a deploy.
* Bad, because there is no way to say "these ten namespaces share a member list".

### A team/organisation entity above namespace

* Good, because one member list can cover many namespaces, which is what a large
  organisation eventually wants.
* Bad, because it introduces a second tenancy level into every visibility function and
  every query that filters by namespace, for a grouping nobody has asked for yet.
* Bad, because it makes the answer to "who can see this" a two-hop question at exactly
  the point where it needs to be cheap and obvious.

### Teams plus per-namespace overrides

* Good, because it is the most expressive: inherit from the team, override where needed.
* Bad, because the effective-role computation becomes a resolution order rather than a
  lookup, and the test surface is the product of both mechanisms.
* Bad, because "why can she see this" stops having a single answer, which is the
  property that makes an authorization model auditable.

### Database-defined roles with an editable capability table

* Good, because a new role is a row and needs no deploy.
* Bad, because it forfeits the build-time matrix: the generated `AUTH_MATRIX.md` becomes
  a snapshot of one row set rather than a statement about the system.
* Bad, because it would put a capability→roles table in SQL alongside the Go one, and a
  drift between two authorization tables is a privilege bug neither side's tests can see.

## More Information

* Supersedes [ADR-025](0025-rbac-visibility.md), whose registry-owned visibility and
  `RequireRegistryOwner` middleware were already replaced by ADR-039 before this epic.
* Builds on [ADR-039](0039-namespace-and-source-model.md), which made the namespace the
  authorization anchor.
* Closes the authorization compromise stated in
  [ADR-044](0044-k8s-inventory-agent.md) Rule K8.
* Migrations 00065 (membership), 00066 (visibility functions), 00067 (drop `owner_id`),
  00068 (key capabilities). Implementation: `internal/authz`, `internal/api/authz.go`,
  `internal/api/authclass.go`.
* The generated operation-by-operation matrix is [docs/AUTH_MATRIX.md](../AUTH_MATRIX.md).
