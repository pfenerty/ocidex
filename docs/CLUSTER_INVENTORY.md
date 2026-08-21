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
| **Running** | Containers in the last snapshot | — |
| **Matched** | Image digest matched an ingested SBOM | Nothing; these are the assessed ones |
| **No SBOM** | Valid registry digest, nothing ingested for it | Ingest the image — see [Gaps](#gaps) |
| **Unresolvable** | The runtime reported no registry-addressable digest | Upgrade the node runtime |

Each tile is a link into the tab that acts on it. Colour marks the tile you have selected, not a
permanent alarm: on a real cluster the gap is never zero, and a tile that is always red carries no
information.

**A vulnerability count never travels without its coverage denominator.** If 40 of 100 containers
are matched, the vulnerability figures describe those 40. The other 60 are *not assessed*, which is
not the same as *clean* — the page says so explicitly wherever a count appears.

## Tabs

### Overview

Most severe running vulnerabilities (top five, linking into the full list), the coverage caveat,
staleness, and the ingest status line: whether auto-ingest is on, and how much of the current gap
is ready to close.

### Workloads

Every reported container, filterable by Kubernetes namespace, match state, and free text over
workload/container/image. Filters live in the URL, so a filtered view is a link you can send
someone. Matched rows carry their image's vulnerability counts, so "which images have
vulnerabilities" is answerable from the table itself.

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
| `ready to ingest` | A registry in this namespace serves this host | Press **Ingest** (or let auto-ingest do it) |
| `no registry` | Nothing in this namespace is configured for that host | Add a registry |
| `registry disabled` | The matching registry is switched off | Enable it |
| `excluded by patterns` | The registry's repository patterns exclude this repo | Widen them, if that is intended |
| `no host in reference` | The reported reference names no registry at all | Node runtime issue; see below |

**No digest readable** — the runtime reported a local image ID rather than a registry digest. No
amount of scanning helps; the remedy is on the node, not in OCIDex.

## Auto-ingest

Registered clusters have **auto-ingest on by default**. Every accepted snapshot queues a scan for
each `ready to ingest` image, so the gap closes on its own wherever OCIDex already has a registry.

- **Scoped to the cluster's own namespace.** A registry in a different namespace is never used,
  even when its host matches — that would pull with credentials this cluster was never granted.
  Such an image is reported as `no registry`.
- **Repeat pushes are free.** Scan jobs are unique per `(registry, digest)`, so reporting the same
  unscanned images every two minutes creates one job for them, ever.
- **Multi-arch images expand.** containerd reports the *index* digest, so OCIDex queues one scan
  per platform rather than one job that would match nothing.
- **Unmatched hosts are reported, not retried.** Nothing about a missing registry changes between
  snapshots.

Turn it off per cluster from the **Auto-ingest** column on the Clusters page (Edit → Save). Editing
a cluster's name never changes the setting.

The **Ingest** buttons on the Gaps tab do the same thing on demand, synchronously, and report
per-reason counts. The bulk button ingests the whole gap; a row button ingests that image only.
Both need `read-write` scope and ownership of the cluster's namespace — the same gate the agent's
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
