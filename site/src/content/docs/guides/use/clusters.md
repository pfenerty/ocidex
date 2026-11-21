---
title: Clusters
description: See what's running in a Kubernetes cluster, how much of it is assessed, and close the gaps.
sidebar:
  order: 6
---

A connected cluster runs the inventory agent, which reports every running container's image.
Connecting one is in the [operator guide](/guides/operate/clusters-and-operator/). The cluster page
answers one question: **what's actually running here, and what do we know about it?**

## The cluster list

The **Clusters** page puts problems first. Each row shows the agent's health with its reason
(*erroring*, *stale*, *never reported*, *healthy* or *paused*), how many containers it runs, how
much of that is assessed, the critical vulnerabilities running in the assessed part, and the agent
and Kubernetes versions. A **skew** badge means the agent and server versions differ.

## The coverage band

![A cluster page: the coverage band, and the most severe vulnerabilities running in the cluster](../../../../assets/screenshots/cluster.png)

A bar above the tabs splits every container in the cluster three ways, and always describes the
**whole cluster**, never the current filter, so a filtered table of three clean rows can't pass for
a clean cluster. Each part of the legend links to the rows behind it.

| Part | Meaning | What to do |
| --- | --- | --- |
| **Matched** (green) | The image digest matches an ingested SBOM | Nothing: these are assessed |
| **No SBOM** (amber) | A valid registry digest, but nothing ingested for it | Ingest it: see [Gaps](#gaps) |
| **No digest readable** (grey) | The container runtime reported no registry digest | Upgrade the node's runtime |

Containers are counted per namespace, workload, container and image, so a three-replica Deployment
is one container and three pods. Every vulnerability figure on the page counts containers.

**A vulnerability count never appears without its coverage.** If 40 of 100 containers are matched,
the counts describe those 40. The other 60 are *not assessed*, which isn't the same as clean, and
the page says so.

Before the agent's first report there's no bar and no inventory tabs, only the install command and
a live wait for the first snapshot. A stale, erroring or paused cluster gets a banner above the bar
that says so, because an old inventory looks exactly like a current one.

## Tabs

The header lists what the agent reported about itself: its version, the Kubernetes version and node
count, how often it reports, and the pod it runs in.

**Overview** shows the five most severe vulnerabilities running in the cluster (headed "top 5 of N")
and whether auto-ingest is on.

**Workloads** shows the inventory two ways, chosen with **Group by**:

- **By image** (the default): one row per running image, with the workloads and pods using it.
  Fourteen deployments of one bad image are one upgrade, so this is usually the view to act from.
- **By workload**: one row per namespace, workload and container, for "where is this running?"

Both open worst-first, and filter by Kubernetes namespace, match state and text. A row that isn't
assessed says so in words, never as a zero.

**Vulnerabilities** lists each advisory once, however many workloads run it. Expand a row to see
which ones do. An advisory's own page shows the reverse: every cluster running it.

**Agent** shows the last pushes with their result and any refusal reason, the cluster's
[agent credentials](/guides/operate/clusters-and-operator/#agent-credentials), its settings (name,
description, auto-ingest), and **Retire…** to pause or delete it. Settings and retiring need the
`manage_cluster` capability.

## Elsewhere in OCIDex

- An **artifact's page** says when it's running and where: a *running in N clusters* badge, a
  **Running** column on its versions, and a **Running** tab listing every workload.
- The **Workspace** clusters panel counts your clusters by health and sums the critical
  vulnerabilities running in them.
- **Search** (⌘K) finds clusters by name.

Clusters are visible only to signed-in users, and only in namespaces you can see.

## Gaps

The **Gaps** tab is the part of the coverage band you can fix.

**No SBOM ingested** lists images, not containers: twelve replicas of one unscanned image are one
thing to ingest. Each row says what's in the way:

| State | Meaning | What to do |
| --- | --- | --- |
| `ready to ingest` | It will be scanned, with the credentials of a registry in this namespace that serves its host, or anonymously when none does | Press **Ingest**, or let auto-ingest do it |
| `scanning` | A scan is queued or running | Wait |
| `pull refused` | The registry answered 401 or 403: the image is private and OCIDex has no working credentials | Add a registry with credentials (the link opens the form with the host filled in), then **Retry** |
| `address refused` | The registry's address is blocked by the egress policy | Ask an operator to allow it, then **Retry** |
| `scan failed` | The image wasn't there, or the scan ran out of attempts | **Retry** |
| `SBOM deleted` | Its SBOM was deleted on purpose | Rescan it from the image's page |
| `registry disabled` | The matching registry is switched off | Enable it |
| `no host in reference` | The reported image names no registry | A node runtime problem |

**Registries to configure** shows the same gap from the fix's side: one registry closes every
image behind it. Each row proposes a registry for one scope (`ghcr.io/acme`, say, since one org's
credentials don't work for another's), in the cluster's namespace, with the repositories it would
need to cover.

**No digest readable** lists containers whose runtime reported a local image id. No scan can help;
the fix is on the node.

The counts above each table describe the whole gap, not the page on screen, so **Ingest all**
queues what it says.

## Auto-ingest

Auto-ingest is **on** for every new cluster: each report queues a scan of every `ready to ingest`
image. Turn it off per cluster in the **Agent** tab's settings, or when connecting it.

- **Credentials come only from the cluster's namespace.** A registry in another namespace is never
  used, even for the same host.
- **Anonymous pulls are guarded** by the same egress policy as everything else, and always use
  HTTPS.
- **A registry's patterns don't limit what's running.** A registry for the host pulls a running
  image with its credentials even if its patterns exclude that repository.
- **Repeat reports cost nothing.** An image that already has a scan job isn't contacted again.
- **One auto-ingest per cluster at a time.** A report that arrives while the previous report's
  auto-ingest is still running doesn't start another. The next report picks up whatever that one
  would have.
- **Refusals aren't retried automatically.** Press **Retry** to ask the registry again.

Ingesting and auto-ingest need the `push_inventory` capability in the cluster's namespace.

Ingest **queues** scans. Rows leave the gap when the scan finishes and the SBOM lands, seconds to
minutes later. A row that stays after its scan finished means the scan failed; the error is on the
**Jobs** page.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| The cluster reads *never reported* | No snapshot has arrived. That's different from running nothing. Check the agent's logs. |
| The cluster reads *erroring* | The agent reaches OCIDex and is refused. The reason is on the pill and the Agent tab. See [Health](/guides/operate/clusters-and-operator/#health). |
| The cluster reads *stale* | No accepted snapshot for three report intervals. The agent is down, or can't reach `server.url`. |
| Workloads vanished after a configuration change | Each report replaces the whole inventory. Narrowing the agent's namespaces removes the others. |
| An image shows as a bare hash | The runtime reported an image id with no name, and the pod spec had none either. |
| Gaps says *This deployment can't scan images* | The installation has no scanner. Nothing can be ingested from OCIDex, and auto-ingest does nothing; upload SBOMs instead. |
| Auto-ingest queues nothing | Check the Gaps tab: every state other than `ready` names its fix. |
