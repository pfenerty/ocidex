---
status: "accepted"
date: 2026-08-16
decision-makers: Patrick Fenerty
---

# Standalone push-based Kubernetes inventory agent

## Context and Problem Statement

OCIDex knows what has been *ingested*: artifacts, SBOMs, components, vulnerabilities. It has no
idea what is *running*. The question a user actually wants answered is not "which of my 4,000
catalogued images has CVE-X" but "these three running Deployments carry CVE-X, and here is which
cluster and namespace they are in". Today that question is unanswerable — there is no workload or
deployment model anywhere in the schema, and the operator's CRDs (`OCIRegistry`, `ScanRequest`,
`APIKey`) are about *ingest configuration*, not about running workloads.

So this is greenfield. The decision to make first is the shape of the connector: how does OCIDex
learn what is running in a cluster, and how cheaply can that be joined back to what it already
knows?

## Decision Drivers

* **Must not require CRDs in the reporting cluster.** The clusters people most want inventoried
  are production clusters where installing a CRD is a change-management event. A connector that
  demands CRD installation will simply not be deployed.
* **Must not require OCIDex to reach the cluster.** Cluster API servers are commonly on private
  networks; OCIDex is commonly not.
* **Must not require OCIDex to hold cluster credentials.** Storing kubeconfigs for N clusters makes
  OCIDex a high-value credential store and a lateral-movement target.
* **Least privilege in the reporting cluster.** Pod read access, nothing else.
* **The join back to catalogued data must be exact, not heuristic.** A "probably this image" match
  in a security view is worse than no match: it reads as a clean bill of health.
* **Must inherit the existing visibility model** (ADR-025, ADR-039) rather than inventing a second
  one.

## Considered Options

* Extend the existing operator with a Pod-watching controller
* Pull model: OCIDex holds a kubeconfig per cluster and lists Pods itself
* Standalone push-based reporting agent, deployed per cluster

## Decision Outcome

Chosen option: **a standalone push-based reporting agent** (`cmd/k8s-agent`), deployed as a
Deployment in each cluster to be inventoried, decoupled from `cmd/operator`. It watches Pods, reads
running image digests, aggregates a snapshot, and POSTs that snapshot to OCIDex on an interval,
authenticated by an API key.

The rules below are normative.

### Rule K1 — The agent is decoupled from the operator

`cmd/k8s-agent` shares no CRD, no controller-runtime manager, and no chart with `cmd/operator`. A
cluster may run the agent, the operator, both, or neither. This is the whole point: inventory
reporting must be installable in a cluster whose owner will not accept CRDs, and the operator's
existing CRDs are about ingest configuration, which is a different concern with a different
audience.

Concretely, the agent needs only a ServiceAccount with `pods: get,list,watch` cluster-wide (or over
an allowlist of namespaces), a Deployment, and a Secret holding the API key.

### Rule K2 — Push, not pull

The agent initiates every connection. OCIDex never dials a cluster API server and never stores a
kubeconfig. The only inbound surface OCIDex exposes is
`POST /api/v1/clusters/{id}/inventory`.

The direct consequence is that OCIDex cannot distinguish "cluster is healthy and empty" from
"agent is dead". That is handled by liveness, not by polling: `cluster.last_seen_at` is stamped on
every accepted snapshot, and a cluster whose `last_seen_at` is stale is reported as **stale**, not
as empty. An inventory view that silently shows zero workloads for a dead agent is the same class
of failure as an unmatched digest reading as clean.

### Rule K3 — The identity reported is the running image digest

The agent reads `status.containerStatuses[].imageID` (and `initContainerStatuses`,
`ephemeralContainerStatuses`), not `spec.containers[].image`. The spec field is a *tag* — mutable,
frequently `:latest`, and therefore not an identity. The status field is what the kubelet actually
resolved and pulled.

`imageID` formats vary by runtime and must be normalised before reporting:

| Observed form | Runtime | Normalised digest |
|---|---|---|
| `docker.io/library/nginx@sha256:abc…` | containerd | `sha256:abc…` |
| `sha256:abc…` | some CRI-O / older kubelets | `sha256:abc…` |
| `docker-pullable://nginx@sha256:abc…` | dockershim era | `sha256:abc…` |
| `docker://sha256:abc…` | dockershim, image ID not repo digest | *unresolvable* — see K5 |

Normalisation extracts the `sha256:` digest after the `@`, or accepts a bare `sha256:` value. The
image *reference* is reported alongside the digest for display, but is never the join key.

### Rule K4 — The join to catalogued data is by digest, and it is exact

`cluster_workload.image_digest` joins `sbom.digest`. ADR-040 makes `sbom.digest` UNIQUE — it is the
sha256 of the artifact itself, and the idempotency guarantee of ingest rests on it. That is what
makes this connector cheap: the join is an equality on a unique indexed column, not a
name-and-tag-and-registry heuristic. There is no identity layering here and deliberately none of
ADR-019's rules; a digest either matches a row or it does not.

This also means the connector gains nothing from and contributes nothing to the diff identity
model. If the join ever needs to become fuzzy, that is a new ADR, not a patch to this one.

**Index-digest fallback.** There is one wrinkle that a strict `sbom.digest` join gets wrong often
enough to make the feature useless. For a multi-arch image pulled by tag, containerd resolves and
records the *image index* digest, so `imageID` carries the index digest — while the scanner
produces one SBOM per platform, whose `sbom.digest` is the per-platform *child manifest* digest and
whose `sbom.index_digest` is the index (ADR-032 lineage, migration `00037`). Joining only on
`sbom.digest` would therefore fail to match the majority of real workloads.

The join is consequently two-tier, and the tier is recorded rather than hidden:

1. `cluster_workload.image_digest = sbom.digest` — an exact per-platform match.
2. otherwise `cluster_workload.image_digest = sbom.index_digest` — the workload is running *some*
   platform of a scanned multi-arch image.

Tier 2 is still exact in the sense that matters (the digest is a cryptographic identity, not a
guess), but it is one-to-many: an index digest may resolve to several per-platform SBOMs. The
cluster reports no platform, so which child is running is genuinely unknown. Resolution is
therefore *deterministic rather than correct-by-construction* — the newest matching SBOM is chosen,
and the match tier is surfaced so a view can say "matched via image index" rather than implying
per-platform precision. Both tiers count as **matched** for K5.

### Rule K5 — Three workload states, and they must be visually distinct

A running workload is in exactly one of:

1. **matched** — its digest equals a `sbom.digest` OCIDex holds. Links through to the artifact,
   SBOM, and vulnerability summary.
2. **unknown** — a valid digest that matches no ingested SBOM. OCIDex knows something is running
   and knows exactly what it is, but has never been given an SBOM for it. This is a *coverage gap*.
3. **unresolvable** — no usable digest could be extracted from `imageID` at all (K3's last row).
   This is an *agent/runtime gap*, not a coverage gap, and is separate because the remedy differs:
   ingest an SBOM versus investigate the node runtime.

The distinction is normative rather than cosmetic. Collapsing unknown or unresolvable into "no
vulnerabilities found" turns an absence of data into an assertion of safety, which is the single
most dangerous thing this feature could do. Any view that reports vulnerability counts over running
workloads MUST also report the count of unmatched workloads alongside it.

### Rule K6 — A cluster is owned by a namespace and inherits its visibility

`cluster.namespace_id` references `namespace`, exactly as `source` does (ADR-039). A cluster
carries no visibility column of its own; every cluster and workload query filters through
`visible_namespace_ids(user_id, is_admin)` like the stats and relationship queries already do.

### Rule K7 — A snapshot is a full replacement, applied transactionally

The agent reports its complete view of the cluster, not a delta. The ingest endpoint upserts every
reported workload and prunes the rows for that cluster that the snapshot did not mention, in one
transaction. Deltas would require the agent to hold reliable state across restarts and would drift
permanently on any missed message; a full snapshot is self-healing by construction.

`first_seen_at` survives an upsert, `last_seen_at` is bumped. A workload that disappears is
deleted, not tombstoned — "what used to run here" is a different feature with a different retention
question, and is out of scope.

### Rule K8 — Authorization reuses `read-write` scope and `ClassOwner`

The inventory endpoint is `ClassOwner` + `Write` in `internal/api/authclass.go`: the caller must
own the namespace that owns the cluster, and a `read`-scoped API key is rejected by
`RequireWrite`. No new API-key scope is introduced.

This settles the open question in `ocidex-zeta.3`. A per-resource scope ("this key may push
inventory to cluster X but may not upload SBOMs") is genuinely narrower and would be the better
answer for an agent credential — but it is a change to the whole API-key model, applying to every
resource, and it belongs to that work (`ocidex-wp9b.2`) rather than being invented here for one
endpoint. Introducing a one-off scope for clusters would leave two scope models to reconcile later.

The interim exposure is stated plainly so it is not discovered later: **an agent's API key can also
upload SBOMs and mutate other resources in namespaces its owner controls.** Mitigation available
today is to give the agent a key belonging to a user who owns only the cluster's namespace.

### Rule K9 — Unknown running images are ingested automatically, within the namespace

*Amendment, epic `ocidex-6zoe`. This answers the last Consequence below: gaps that "appear forever
until someone ingests them" now close themselves wherever OCIDex already has a registry for them.*

An accepted snapshot ends by submitting a scan job for every running image with **no SBOM** whose
registry host resolves to an enabled registry **in the cluster's own namespace**. Resolution never
crosses a namespace boundary: using another namespace's registry would pull with credentials this
cluster was never granted, and K6 already says a cluster sees only what its namespace can see.

Three properties make this safe to run on every push rather than on a schedule:

* **Repeat runs enqueue nothing.** Scan jobs are keyed on `registry_id@digest` (ADR-024), so a
  cluster that reports the same unscanned images every two minutes creates exactly one job for
  them, ever. No dedup state was added; the queue's existing uniqueness is the whole mechanism.
* **The trigger does not block the push.** It runs in a goroutine with its own timeout and a
  context detached from the request, because a snapshot must not wait on registry round-trips for
  hundreds of images. The explicit `POST /clusters/{id}/ingest-unknown` runs synchronously instead
  and returns the counts, which is what makes the UI button honest.
* **Index digests expand.** containerd reports the *index* digest for a multi-arch image (K3), so a
  reported digest is HEAD-ed first and, when it is an index, submitted as one job per platform with
  `IndexDigest` set — the tier-two match in K4. Submitting the index digest alone would queue work
  that matches nothing.

**A host with no registry is reported, not retried.** `no_registry`, `registry_disabled`,
`pattern_excluded` and `unparseable_ref` are four separate counters and four separate row states in
the UI, never one "could not ingest" total. This is K5's argument applied to the ingest side: the
remedies are *add a registry*, *switch this one on*, *widen its patterns*, and *fix the node
runtime*, and collapsing them sends every reader to the wrong one. Retrying instead would be worse
than useless — nothing about a missing registry changes between snapshots, so a retry loop would
spend credentials it does not have against a host it cannot reach, forever.

Auto-ingest is per cluster (`cluster.auto_ingest`) and **defaults to on**: a cluster that reports
what it runs and then leaves it unscanned is precisely the gap the inventory exists to close. It is
a `PATCH`-omission field, so editing a cluster's name cannot switch ingest off as a side effect.
Ownership, not visibility, gates the endpoint — it spends the namespace's registry credentials and
enqueues work, so it carries the same `ClassOwner` + `Write` gate as the inventory push (K8).

### Consequences

* Good, because a cluster can be inventoried without CRDs, without inbound network access, and
  without OCIDex holding any cluster credential.
* Good, because the join is an equality on a UNIQUE column — cheap, exact, and impossible to
  misattribute.
* Good, because it reuses the namespace ownership and visibility model wholesale; there is no
  second authorization model to keep in sync.
* Good, because full-snapshot semantics make the write path self-healing: a missed push costs
  freshness, never correctness.
* Bad, because coverage depends on an agent being deployed and alive in every cluster. K2's
  staleness reporting bounds the damage but does not remove it.
* Bad, because the agent's credential is broader than the job requires until per-resource scopes
  exist (K8).
* Bad, because a full snapshot is O(pods) on every interval. Acceptable at the scale of one
  Deployment reporting a few thousand pods every few minutes; if it stops being acceptable, the
  answer is a longer interval or a content hash short-circuit, not deltas.
* Bad, because workloads whose image was deleted from the registry, or that run from a digest never
  ingested, appear as coverage gaps forever until someone ingests them. That is honest reporting,
  but it is noise until coverage is good. K9 removes most of it: a gap OCIDex has a registry for
  closes on the next snapshot. What remains — images from hosts no registry covers — is the part
  that genuinely needs a human, and it is reported as such.
* Bad, because K9 makes an accepted snapshot spend the namespace's registry credentials without a
  human in the loop. Bounded by the namespace scope, the enabled-registry check, and each
  registry's repository patterns; a namespace that wants none of it sets `auto_ingest` to false.

### Confirmation

* Schema and visibility: `ocidex-zeta.2` — migration up/down, and a test proving a cluster in a
  non-visible namespace is absent from every listing.
* Ingest semantics: `ocidex-zeta.3` — an integration test proving a non-owner API key is rejected
  (K6, K8) and that a second snapshot prunes workloads absent from it (K7).
* Digest normalisation: `ocidex-zeta.4` — table-driven tests over every `imageID` form in K3,
  including the unresolvable one.
* End to end: verified against `make dev-cluster-up`, with workloads running in the dev cluster
  appearing in the API afterwards.
* Auto-ingest (K9): `ocidex-6zoe.8` — an integration test over a snapshot carrying one image per
  reason (enabled registry, disabled registry, pattern-excluded repository, and a matching registry
  in a *different* namespace) asserting one queued job and three distinctly-counted skips; unit
  tests over index expansion and over every skip reason reaching its own counter.

## Pros and Cons of the Options

### Extend the existing operator with a Pod-watching controller

* Good, because there is already an operator, a chart, and controller-runtime wiring to reuse.
* Good, because a `ClusterInventory` CRD would make configuration declarative and GitOps-friendly.
* Bad, because it couples inventory reporting to CRD adoption. Every cluster that wants inventory
  would have to accept OCIDex's CRDs, which is exactly the population most likely to refuse.
* Bad, because it conflates two unrelated concerns: the operator configures *ingest*, the agent
  reports *runtime state*. They have different blast radii and different RBAC needs, and bundling
  them means the inventory feature inherits the operator's permissions.

### Pull model: OCIDex holds a kubeconfig per cluster

* Good, because there is nothing to install in the target cluster at all.
* Good, because OCIDex controls polling cadence centrally and knows immediately when a cluster is
  unreachable.
* Bad, because it requires network reachability from OCIDex to every cluster API server, which is
  usually false and often not fixable.
* Bad, because it makes OCIDex a store of cluster credentials — a far more attractive target than a
  store of SBOMs, and a much worse breach.
* Bad, because credential rotation across N clusters becomes OCIDex's problem.

### Standalone push-based agent

* Good, because it inverts the network direction: outbound-only from the cluster.
* Good, because RBAC is `pods: get,list,watch` and nothing else, auditable at a glance.
* Good, because it follows the existing worker conventions (`internal/config`, ADR-027 lifecycle
  logging and `--once`, distroless stage per ADR-038) rather than introducing a new binary shape.
* Bad, because something must be installed and kept alive in every cluster.
* Bad, because OCIDex cannot tell an empty cluster from a dead agent without the staleness rule.

## More Information

* Digest uniqueness — the property the whole join rests on — is normative in
  [ADR-0040 — Non-container artifact identity](0040-non-container-artifact-identity.md).
* Visibility and ownership: [ADR-0025 — RBAC and visibility](0025-rbac-visibility.md) and
  [ADR-0039 — Namespace and source model](0039-namespace-and-source-model.md).
* Binary conventions: [ADR-0027 — Ephemeral job contract](0027-ephemeral-job-contract.md) for
  `--once` and lifecycle logging; [ADR-0038 — Web serving and base image policy](0038-web-serving-and-base-image-policy.md)
  for the distroless runtime stage.
* Operator scope, deliberately not extended here:
  [ADR-0030 — K8s operator and CRDs](0030-k8s-operator-crds.md).
* Epic: `ocidex-zeta` — Kubernetes deployment inventory.

### Non-goals

Recorded so they are not silently revisited:

* **A `ClusterInventory` CRD.** Reopen only if declarative, GitOps-managed agent configuration is
  demanded by users who have already accepted CRDs — and then as an *optional* layer over the
  agent, never as its only configuration path.
* **Historical workload retention.** `cluster_workload` is a current-state table (K7). "What ran
  here last month" is a time-series question needing its own retention and storage decision.
* **Fuzzy image matching.** The value of K4 is that a match is a fact. Reopen only with a concrete
  case that digest matching cannot express at all.
* **Non-Pod workload sources** (VMs, serverless, bare processes). The digest join would still hold;
  the agent would not. A different reporter, same ingest contract.
