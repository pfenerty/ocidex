---
title: Clusters and the operator
description: Install the cluster inventory agent, and the optional Kubernetes operator.
sidebar:
  order: 5
---

## The inventory agent

`ocidex-k8s-agent` reports which images a Kubernetes cluster is running, so OCIDex can show what's
[running and what's covered](/concepts/clusters-and-coverage/). It is a separate chart, installed
once in **each cluster you want inventoried**, which usually aren't the cluster OCIDex runs in. It
needs no database, NATS or CRDs: it lists pods and sends a snapshot to the API over HTTPS.

### Install

On the **Clusters** page, choose **Connect a cluster**. Name it and pick the namespace that owns it.
OCIDex creates the cluster and an **agent credential**, then shows one command to run against the
target cluster:

```sh
helm install ocidex-k8s-agent oci://ghcr.io/pfenerty/charts/ocidex-k8s-agent \
  --namespace ocidex-agent --create-namespace \
  --set server.url=https://ocidex.example.com \
  --set cluster.id=<cluster id> \
  --set apiKey.value=<key>
```

The page then waits for the agent's first report and updates by itself. If the agent reports but
OCIDex refuses it, the page says why (see [Health](#health)).

The key is shown once. If you leave the page before installing, open the cluster again and choose
**Get install command**: that mints a new credential, and the old one keeps working until you
revoke it.

`server.url` is the API's public URL (`API_BASE_URL` when it's set). It's usually outside the
target cluster, so it must be reachable from there, and its TLS certificate must validate there.

#### Keeping the key out of Helm values

`--set apiKey.value` makes the chart create the Secret, so the key is stored in the Helm release.
Where values live in Git, choose the **values.yaml** form instead. It names a Secret you create
yourself (sealed-secrets, external-secrets, or `kubectl`), and leaves `apiKey.value` empty:

```yaml
server:
  url: https://ocidex.example.com
cluster:
  id: <cluster id>
apiKey:
  secretName: ocidex-k8s-agent-secrets
  secretKey: OCIDEX_API_KEY
```

#### With the API

```sh
curl -fsS -X POST https://ocidex.example.com/api/v1/clusters/connect \
  -H "Authorization: Bearer $OCIDEX_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"prod-eu","namespaceId":"<namespace id>"}'
```

The response holds the cluster and its first credential, with the key. Connecting needs the
`manage_cluster` and `push_inventory` capabilities in that namespace.

### Agent credentials

An agent credential is an API key bound to one cluster. It can push that cluster's inventory and
nothing else: every other request is refused, public reads included. Manage credentials on the
cluster's **Agent** tab: mint, **Rotate** (the old key stops working at once), and **Revoke**.
Each one shows who minted it and when it was last used.

A credential acts with the roles of whoever minted it, so it stops working if they lose the ability
to push in that namespace. Rotating re-mints it under your name. Deleting the cluster revokes all
of its credentials.

To rotate without downtime, mint a second credential, roll the agent onto it with
`helm upgrade ... --set apiKey.value=<new key>` (the pod restarts on its own), then revoke the
first.

An ordinary API key with the `push_inventory` capability still works as an agent key. It isn't
limited to one cluster, though.

### Health

Every push is recorded, refused ones included, and each cluster shows one state:

| State | Meaning |
| --- | --- |
| **healthy** | The last push was accepted, and recently |
| **stale** | No accepted push within three of the agent's report intervals |
| **erroring** | The agent is pushing and OCIDex is refusing it. The reason says why. |
| **never reported** | Nothing has arrived yet |
| **paused** | Someone paused the cluster; pushes are refused on purpose |

The cluster's **Agent** tab lists the last pushes with their result. Common refusals:

| Reason | Fix |
| --- | --- |
| The API key was not accepted | The credential was revoked or rotated. Install a new one. |
| A credential for a different cluster | `cluster.id` doesn't match the credential. Check the values. |
| The key may not push here | The key's owner lost `push_inventory` in this namespace |
| The snapshot failed validation | Agent and server versions are far apart. Upgrade the agent chart. |

The agent logs the same reason (`inventory push rejected`, with `status` and `reason` fields).
It also reports its version, the Kubernetes version, its node count and its report interval, which
the cluster page shows. When agent and server versions differ by a minor version or more, the page
flags it.

For alerting, the API exports `ocidex_cluster_health{cluster,namespace,state}`, which is 1 on the
cluster's current state:

```text
ocidex_cluster_health{state=~"stale|erroring"} == 1
```

The agent exports `ocidex_agent_pushes_total{outcome,status}`.

### Check it

`kubectl -n ocidex-agent logs deploy/ocidex-k8s-agent` shows an `inventory reported` line with
counts of pods, workloads and unresolvable images, and the cluster page turns healthy.

A non-zero unresolvable count is a real signal: those containers' runtime reports no registry
digest, usually because of an old node runtime, so they can never be matched to an SBOM.

### Retiring a cluster

On the **Agent** tab, choose **Retire…**. First uninstall the agent
(`helm uninstall ocidex-k8s-agent -n ocidex-agent`), then either:

- **Pause**: pushes are refused and everything is kept. The last inventory stays readable, the
  images it lists stay protected from retention, and credentials keep their keys. Resume at any
  time.
- **Delete**: the inventory goes, the credentials are revoked, and SBOMs ingested from the cluster
  stay but no longer record where they came from. Images that ran only there lose their
  protection from retention.

### Things that look like bugs and aren't

- **Each snapshot replaces the cluster's whole inventory.** Narrowing the agent's namespaces
  therefore removes the dropped namespaces' workloads on the next push.
- **Never run two agents for one cluster id.** Their snapshots would replace each other in turn.
  The Deployment uses `maxSurge: 0` for this reason.

### Auto-ingest

Every cluster has auto-ingest on by default: each snapshot queues a scan of every
running image that has no SBOM yet. OCIDex pulls it with the credentials of a registry in the
cluster's namespace that serves its host, or anonymously when none does. Expect a burst of scans
after the first snapshot.

### As a CronJob

The agent also accepts `--once`: send one snapshot, then exit. The chart only renders the
long-running Deployment, so to run it on a schedule, use the image in your own CronJob with
`args: ["--once"]` and the same environment.

## The operator

`ocidex-operator` lets you manage OCIDex registries, scans and API keys as Kubernetes resources:
`OCIRegistry`, `ScanRequest` and `APIKey`. It reconciles them through the OCIDex API. It is
**alpha**, with no compatibility guarantee.

The operator acts with its own API key, so its capabilities bound what it can do. An
`APIKey` resource may only ask for capabilities the operator's key holds itself (an empty
list asks for all of them), and the operator may only delete keys within the same bound.
Give the operator a key with every capability you want its `APIKey` resources to grant.

```sh
kubectl -n ocidex-operator create secret generic ocidex-operator-secrets \
  --from-literal=OCIDEX_API_KEY="$OCIDEX_API_KEY"

helm install ocidex-operator oci://ghcr.io/pfenerty/charts/ocidex-operator \
  -n ocidex-operator --version <version> \
  --set server.url=http://ocidex-api.ocidex.svc.cluster.local \
  --set watchNamespace=ocidex
```

```yaml
apiVersion: ocidex.io/v1alpha1
kind: OCIRegistry
metadata:
  name: acme
  namespace: ocidex
spec:
  name: acme
  type: ghcr
  url: ghcr.io
  repositories: ["acme/api", "acme/worker"]
```

An `OCIRegistry` belongs to the OCIDex namespace named by `spec.namespace`, or by default to one
named after its own Kubernetes namespace.

### Upgrading its CRDs

Helm installs CRDs but never upgrades them. With Flux, set `install.crds: CreateReplace` and
`upgrade.crds: CreateReplace` on the HelmRelease. With the Helm CLI, apply the new chart's CRDs
first:

```sh
helm pull oci://ghcr.io/pfenerty/charts/ocidex-operator --version <new> --untar
kubectl apply --server-side -f ocidex-operator/crds/
helm upgrade ocidex-operator oci://ghcr.io/pfenerty/charts/ocidex-operator --version <new>
```

### Changing what it watches, or removing it

Each `OCIRegistry` carries a finalizer that only an operator watching its namespace can remove.
Changing `watchNamespace`, or uninstalling, while registries still exist leaves them stuck, and
their Kubernetes namespace can never finish deleting.

**To remove the registries:** delete them while the operator still watches, wait until
`kubectl get ociregistries -n <ns>` is empty, then change `watchNamespace` or uninstall.

**To move them:** `watchNamespace` takes a comma-separated list, so overlap the scopes:

1. `helm upgrade ... --set watchNamespace=<old>,<new>`.
2. Recreate the resources in `<new>`, then delete them from `<old>`.
3. When `<old>` is empty, `helm upgrade ... --set watchNamespace=<new>`.

If a namespace is already stuck, see [Troubleshooting](/guides/operate/troubleshooting/#a-namespace-stuck-terminating).
