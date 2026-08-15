# Local Kubernetes Dev Loop (Talos + Tilt)

This guide covers the full local K8s development loop using a Docker-backed Talos cluster and Tilt for live reloading.

## Prerequisites

All required tools (`talosctl`, `tilt`, `kubectl`) are pinned in the Flox environment. Run all commands inside `flox activate`.

Required on the host (outside Flox):
- Docker Desktop or Docker Engine

The loop is verified on both Linux and macOS. Two things differ on macOS, and `make dev-cluster-up`
handles both for you:

- **`br_netfilter`** must be loaded in the kernel that runs the containers. On Linux that is this
  host; on macOS it is Docker Desktop's LinuxKit VM, so the preflight probes the VM rather than
  the host `/proc`. If it reports the module missing, load it with
  `docker run --rm --privileged --network=host busybox modprobe br_netfilter`.
- **The API endpoint.** `talosctl kubeconfig` writes the node's in-cluster address
  (`10.5.0.2:6443`), which is unreachable from macOS because the Docker bridge lives inside the
  VM. The target retargets the kubeconfig at the `127.0.0.1` port the provisioner publishes.

Docker Desktop needs enough headroom for a Talos control plane and worker plus twelve workloads
alongside the Go image builds. Verified working at 8 CPUs / 8 GB.

## One-Time Cluster Setup

Run once per session (or after `make dev-cluster-down`):

```bash
flox activate -- make dev-cluster-up
```

This creates a Talos cluster backed by Docker and wires it to a local registry on `localhost:5005`. Images pushed to `localhost:5005` are automatically available inside the cluster via a registry mirror on `10.5.0.1:5005`.

## Start the Dev Stack

```bash
flox activate -- make dev-up
```

Tilt builds the API, worker, and web images, pushes them to the local registry, and applies the `charts/ocidex` Helm chart rendered with `tilt/values-dev.yaml` plus the dev-only Postgres in `tilt/postgres.yaml`. It watches source files and rebuilds on change.

Tilt UI: [http://localhost:10350](http://localhost:10350)

### Access the App

| Service | Address | Notes |
|---------|---------|-------|
| API | http://localhost:8080 | Port-forwarded from the cluster |
| Frontend | http://localhost:3000 | Vite dev server (HMR); proxies `/api/*` to `:8080` |

Start the frontend dev server separately:

```bash
flox activate -- make frontend-dev
```

### Seed Data

Seeding registers a set of well-annotated public repositories (quay.io and ghcr.io) as
registries and triggers a scan on each. It needs an API key with write scope: log in at
http://localhost:3000, then create one under **Settings → API Keys**.

```bash
export OCIDEX_API_KEY=ocidex_...
flox activate -- make seed
```

`make seed` blocks until the first artifacts land, then exits — **scanning continues in the
background**. The catalog walk is queued asynchronously and `scanner-worker` runs syft per
image, so the full set (45 images across 11 repos) takes a while. Watch progress in the
`ocidex-scanner-worker` resource in the Tilt UI, or poll:

```bash
# /artifacts is cursor-paginated (hasMore, no total) and defaults to 20 per
# page — raise limit, and follow .pagination.hasMore if it stays true.
curl -s -H "Authorization: Bearer $OCIDEX_API_KEY" \
  'http://localhost:8080/api/v1/artifacts?limit=100' | jq '.data | length'
```

Re-running is safe: registries that already exist are resolved and re-scanned rather than
duplicated. Pass extra flags via `SEED_ARGS`, e.g. `make seed SEED_ARGS=--all-tags` to ingest
every semver tag instead of the pinned minor per repo, or `SEED_ARGS=--no-scan` to register
without scanning.

## Stopping

```bash
flox activate -- make dev-down         # Stop Tilt (keeps cluster running)
flox activate -- make dev-cluster-down # Destroy the cluster and registry
```

## How It Works

- `make dev-cluster-up` runs `talosctl cluster create` with a custom registry-mirror config (`tilt/talos-cluster.yaml`) so pods pull from the host's bridge IP `10.5.0.1:5005`.
- `make dev-up` runs Tilt, which reads `Tiltfile` at the repo root. The Tiltfile generates the `ocidex-secrets` Secret from the local `.env` file, overriding `DATABASE_URL` to point at the in-cluster Postgres, then builds the images and applies the chart.
- `tilt/values-dev.yaml` scales every Deployment to 1 replica, sets `NATS_STREAM_REPLICAS=1`, and backs NATS with an `emptyDir` (the Talos-in-Docker cluster has no default StorageClass, so a PVC would stay `Pending`).

### The database

`charts/ocidex` renders **no** Postgres workload — per ADR-031 the database is external to this repo, and production runs a CloudNativePG `Cluster` declared in the homelab Flux repo. The dev loop supplies its own from `tilt/postgres.yaml`: a single-replica `postgres:18.4-alpine` Deployment plus a Service named `postgres`, matching the host in the Tiltfile's `DATABASE_URL`.

Its credentials are `ocidex:ocidex`, the same as `.env` and `docker-compose.yml`, and it is port-forwarded to host `5432` — so `make migrate-up`, `make seed`, and `psql` work from the host against the cluster database with no extra setup.

Schema is applied in-cluster by `tilt/values-dev.yaml` setting `migrate.enabled: true`, which renders the chart's migrate Job as the Tilt resource `ocidex-migrate-1` (gated on `postgres` being ready). It runs the same `ocidex migrate up` that production does.

**The dev database is `emptyDir`-backed and is wiped whenever its pod restarts.** After a restart, reapply the schema with `tilt trigger ocidex-migrate-1` — no need for a full `tilt down`.

`resource_deps` only *orders* the initial build; it does not re-run migrate when postgres restarts on its own. So a bare pod loss leaves you with every resource green and an empty database, and the first symptom is `relation "sbom" does not exist` in the API log rather than anything failing outright. The Deployment uses `strategy: Recreate` so that a postgres change Tilt *does* know about can't run migrate against the outgoing pod, but nothing covers a pod dying by itself — re-trigger migrate by hand.

## Troubleshooting

**Pods stuck in `ImagePullBackOff`:** Confirm the image was pushed to `localhost:5005`. Check `tilt` logs in the Tilt UI. Verify the cluster is running: `talosctl cluster show`.

**Port-forward drops:** Re-run `make dev-up` — Tilt automatically re-establishes port-forwards on restart.

**Tiltfile fails at startup:** The Tiltfile hard-fails unless `.env` exists at the repo root with `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and `SESSION_SECRET` set. `DATABASE_URL` and `NATS_URL` are overridden with in-cluster addresses, so whatever `.env` holds for those is ignored. See `.env.example`.

**Pods report `relation ... does not exist`:** The Postgres pod restarted and its `emptyDir` went with it. Run `tilt trigger ocidex-migrate-1`.

**NATS issues in dev:** The dev overlay sets `NATS_STREAM_REPLICAS=1` (single-node NATS). If you recreate the cluster, NATS stream state is lost — this is expected for dev.
