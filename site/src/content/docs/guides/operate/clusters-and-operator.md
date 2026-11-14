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

1. **Register the cluster** in OCIDex, under the namespace it should belong to: on the
   **Clusters** page, or with the API. Note its id.

   ```sh
   curl -fsS -X POST https://ocidex.example.com/api/v1/clusters \
     -H "Authorization: Bearer $OCIDEX_API_KEY" -H 'Content-Type: application/json' \
     -d '{"name":"prod-eu","namespaceId":"<namespace id>"}'
   ```

2. **Create an API key for the agent.** It needs the `push_inventory` capability, and its owner
   needs a role that grants it in that namespace (owner, maintainer or developer). Put it in a
   Secret in the target cluster:

   ```sh
   kubectl create namespace ocidex-agent
   kubectl -n ocidex-agent create secret generic ocidex-k8s-agent-secrets \
     --from-literal=OCIDEX_API_KEY="$OCIDEX_API_KEY"
   ```

3. **Install the chart**, against the target cluster:

   ```sh
   helm install ocidex-k8s-agent oci://ghcr.io/pfenerty/charts/ocidex-k8s-agent \
     -n ocidex-agent --version <version> \
     --set server.url=https://ocidex.example.com \
     --set cluster.id=<cluster id>
   ```

`server.url` is usually outside the target cluster, so it must be reachable from there, and its TLS
certificate must validate there.

### Check it

`kubectl -n ocidex-agent logs deploy/ocidex-k8s-agent` shows an `inventory reported` line with
counts of pods, workloads and unresolvable images, and the cluster's page in OCIDex fills in. A
cluster that reads *never reported* hasn't received a snapshot at all, which is different from a
cluster running nothing.

A non-zero unresolvable count is a real signal: those containers' runtime reports no registry
digest, usually because of an old node runtime, so they can never be matched to an SBOM.

### Things that look like bugs and aren't

- **Each snapshot replaces the cluster's whole inventory.** Narrowing the agent's namespaces
  therefore removes the dropped namespaces' workloads on the next push.
- **Never run two agents for one cluster id.** Their snapshots would replace each other in turn.
  The Deployment uses `maxSurge: 0` for this reason.

### Auto-ingest

Every registered cluster has auto-ingest on by default: each snapshot queues a scan of every
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
