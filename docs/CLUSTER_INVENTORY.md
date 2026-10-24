# Cluster Inventory Guide

A registered cluster runs the `ocidex-k8s-agent` (see
[DEPLOYMENT.md](DEPLOYMENT.md#cluster-inventory-agent-separate-chart-per-target-cluster)), which
pushes a snapshot of every running container's image. This guide covers what the cluster page
tells you, and what to do about each thing it reports.

## The question the page answers

**"What is actually running here, and what do I know about it?"** Everything on the page is a
consequence of that: coverage is how much of the cluster OCIDex can speak to, vulnerabilities are
counted over the part it can, and the gap is the part it cannot — stated rather than hidden.

## The coverage band

Four tiles, always visible above the tabs, always describing the **whole cluster** — never the
current filter. A filtered table showing three clean rows must not read as a clean cluster.

| Tile | Meaning | What to do |
|---|---|---|
| **Running** | Workload containers in the last snapshot, with the pod total beneath | — |
| **Matched** | Image digest matched an ingested SBOM | Nothing; these are the assessed ones |
| **No SBOM** | Valid registry digest, nothing ingested for it | Ingest the image — see [Gaps](#gaps) |
| **Unresolvable** | The runtime reported no registry-addressable digest | Upgrade the node runtime |

The Running tile counts **workload containers**, not pods and not distinct images: one row per
`(namespace, workload, container, image)`, which is the unit the other three tiles partition. The
pod figure beneath it is the replica total those containers add up to, so a 3-replica Deployment is
one container and three pods. Every vulnerability figure on the page is denominated in the first
number, never the second.

Each tile is a link into the tab that acts on it. Colour marks the tile you have selected, not a
permanent alarm: on a real cluster the gap is never zero, and a tile that is always red carries no
information.

**A vulnerability count never travels without its coverage denominator.** If 40 of 100 containers
are matched, the vulnerability figures describe those 40. The other 60 are *not assessed*, which is
not the same as *clean* — the page says so explicitly wherever a count appears.

## Tabs

### Overview

Most severe running vulnerabilities — five rows, each carrying its severity, id, CVSS score,
summary and the number of workloads running it, headed "top 5 of N" so the five are never mistaken
for the whole list. Then the coverage caveat, staleness, and the ingest status line: whether
auto-ingest is on, and how much of the current gap is ready to close.

**Before the first snapshot** the Overview shows agent-install commands instead, carrying this
cluster's own id. A registered cluster with nothing in it is the expected first state, not a fault
— the agent runs in the target cluster, which may be nowhere near this one — so the page says what
is missing rather than showing four zeroed tiles that read as a clean cluster.

### Workloads

Two groupings of the same inventory, switched with the **Group by** control and carried in the URL
as `group`, so either view is a link you can send someone:

- **By image** (the default) — one row per running image, with the workload and pod counts it
  accounts for. This is the unit of most remedies: fourteen deployments of one bad image are one
  upgrade, and by-workload would show that as fourteen rows saying the same thing.
- **By workload** — one row per `namespace/workload · container`, for the other question: *where is
  this actually running?*

Both open on **worst findings first** rather than alphabetically by namespace, so the first screen
is the actionable one, and both filter by Kubernetes namespace, match state, and free text over
workload/container/image. Changing the grouping keeps your filters and resets the sort, since the
two groupings do not share every sort key.

Matched rows carry their image's vulnerability counts, so "which images have vulnerabilities" is
answerable from the table itself. An unassessed row says so in words — it never shows a zero, and
it sorts last in either direction rather than ranking beside a genuinely clean one.

### Vulnerabilities

Advisories carried by the images this cluster is actually running, counted **once per advisory**
rather than once per workload, and keyed by canonical id — so an advisory published as `GHSA-…`,
`GO-…` and `CVE-…` is one row, not three. Expanding a row shows which workloads run it.

The reverse view lives on each vulnerability's own page ("Running in your clusters"), which answers
the question the catalog alone cannot: *am I running this?*

### Gaps

The actionable half of the coverage band, split by remedy.

**No SBOM ingested** — listed by *image*, not by container: twelve replicas of one unscanned image
are one thing to ingest. Each row says what stands between it and an SBOM:

| Row state | Meaning | Remedy |
|---|---|---|
| `ready to ingest` | Will be queued next run: with the credentials of a registry in this namespace that serves the host, or anonymously (`anonymous pull`) when none does | Press **Ingest** (or let auto-ingest do it) |
| `scanning` | A scan job is queued or running | Wait |
| `pull refused` | The host answered 401/403, so the image is private and OCIDex has no credentials that work | Add a registry with credentials — the link opens the add dialog with the host filled in — then press **Retry** |
| `address refused` | The host resolves to an address the egress policy refuses | Allow it in the egress policy, then **Retry** |
| `scan failed` | The manifest was not there, or the scan used up its attempts | **Retry** |
| `SBOM deleted` | Its SBOM was deleted on purpose | Rescan it from the image's page; cluster ingest does not bring it back |
| `registry disabled` | The matching registry is switched off | Enable it |
| `no host in reference` | The reported reference names no registry at all | Node runtime issue; see below |

Both link into **Sources**, where registries are managed: `pull refused` opens the add dialog
prefilled with the host that refused, and a named registry opens its editor. You do not need to
be an administrator — owning the cluster's namespace is enough, and the Sources entry appears in the
nav for anyone signed in.

**Registries to configure**, above the image list, is the same gap seen from the remedy's side. The
image list is the unit of an *ingest*; a registry is the unit of *configuration*, and one registry
closes every image behind it at once. Each row carries the whole gap's totals — never the page on
screen — and the repositories a registry would have to cover, so the prefill is visible before it is
clicked.

Rows are grouped by **registry scope**, not by hostname. On a multi-tenant host the credentials stop
working below the host, so `ghcr.io/orgA` and `ghcr.io/orgB` are two rows proposing two registries;
`registry.k8s.io` and a self-hosted Zot are one row each. How deep a host splits is a table in
`internal/service/cluster_ingest.go` (`registryTenancyDepth`):

| Host | Segments owned by the registry |
|---|---|
| `ghcr.io`, `quay.io`, `docker.io`, `*.gcr.io`, `public.ecr.aws` | 1 — the account or org |
| `*-docker.pkg.dev` (Artifact Registry) | 2 — project and repository |
| ECR, ACR, `registry.k8s.io`, `mcr.microsoft.com`, anything unknown | 0 — the host is the registry |

An unknown host deliberately stays whole. Under-splitting proposes one registry where two were
needed, which the reader sees and corrects; over-splitting proposes registries that each work and
quietly stops finding new repositories, because a split registry is pinned to an explicit repository
list. Adding a host to the table is a one-line change when a real one is misgrouped.

The row's scope names the created registry (`ghcr.io/orgA`); its **URL** stays the host, because
that is the address. The dialog also opens with the *cluster's* namespace, since registry resolution
is namespace-local — a registry created into a namespace of its own closes nothing here.

**No digest readable** — the runtime reported a local image ID rather than a registry digest. No
amount of scanning helps; the remedy is on the node, not in OCIDex.

Both tables paginate. The counts above them — the size of the gap, and how much of it is ready to
ingest — describe the **whole gap**, not the page on screen, so the bulk button's figure is what it
will actually queue.

## Auto-ingest

Registered clusters have **auto-ingest on by default**. Every accepted snapshot queues a scan for
each `ready to ingest` image, so every image the cluster runs gets an SBOM unless its host refuses
the pull (ADR-0044 K10).

- **Credentials come from the cluster's own namespace.** A registry in a different namespace is
  never used, even when its host matches — that would pull with credentials this cluster was never
  granted. Such an image, and any image from a host no registry serves, is pulled anonymously.
- **Anonymous pulls are guarded.** They go through the same egress policy as registry traffic and
  always use HTTPS; a plain-HTTP registry needs a configured registry with `insecure` set.
- **Patterns scope the catalog walk, not running images.** A registry for the host pulls a running
  image with its credentials even when its repository patterns, or its explicit repositories list,
  exclude the repository.
- **Attribution.** An image a registry's patterns select is that registry's SBOM, exactly as if its
  catalog walk had found it. Anything else belongs to the cluster: each cluster has a source of
  kind `cluster` in its namespace, and retention keeps the newest versions of those SBOMs per
  series once the image stops running.
- **Repeat pushes are free.** An image that already has a scan job, in any state but succeeded, is
  skipped before any network call, so reporting the same images every two minutes contacts no host.
- **Multi-arch images expand.** containerd reports the *index* digest, so OCIDex queues one scan
  per platform rather than one job that would match nothing.
- **Refusals are recorded, not retried.** A 401/403, an egress refusal or a missing manifest is
  stored as a failed job and counted on every later run. Pressing **Retry** on the row is what asks
  the host again.

Turn it off per cluster from the **Auto-ingest** column on the Clusters page (Edit → Save). Editing
a cluster's name never changes the setting.

The **Ingest** buttons on the Gaps tab do the same thing on demand, synchronously, and report
per-reason counts. The bulk button ingests the whole gap; a row button ingests that image only.
Both need the `push_inventory` capability on the cluster's namespace — the same gate the agent's
own push uses.

### Queued is not scanned

Ingesting enqueues work. Rows move out of the gap when a scanner worker finishes and the SBOM
lands, which is seconds to minutes later depending on image size and queue depth. Watch progress on
the **Jobs** page. A row that stays in the gap after its job completed means the scan itself
failed — the job's error is on that page, not here.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Cluster reads `never reported` | The agent has never pushed. Not the same as a cluster running nothing — check `kubectl -n ocidex-agent logs deploy/ocidex-k8s-agent` |
| Workloads disappeared after a config change | Every push replaces the whole inventory (ADR-044 K7). Narrowing the agent's `namespaces` deletes the dropped ones |
| An image shows as a bare hash | The runtime reported an image ID with no reference. The agent prefers the pod spec's image name when this happens; a row still showing hex had neither |
| Auto-ingest queues nothing | Check the Gaps tab: every non-`ready` reason names its own remedy. If all rows are `ready` and nothing queues, the deployment has no scanner configured |

## See also

- [ADR-0044 — K8s inventory agent](adr/0044-k8s-inventory-agent.md) — normative rules, including
  K3 (digest normalization), K5 (the states must stay distinct) and K9 (auto-ingest).
- [DEPLOYMENT.md](DEPLOYMENT.md#cluster-inventory-agent-separate-chart-per-target-cluster) —
  installing the agent.
