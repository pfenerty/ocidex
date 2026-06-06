# Local Kubernetes Dev Loop (Talos + Tilt)

This guide covers the full local K8s development loop using a Docker-backed Talos cluster and Tilt for live reloading.

## Prerequisites

All required tools (`talosctl`, `tilt`, `kubectl`) are pinned in the Flox environment. Run all commands inside `flox activate`.

Required on the host (outside Flox):
- Docker Desktop or Docker Engine

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

Tilt builds the API and worker images, pushes them to the local registry, and applies `k8s/overlays/dev`. It watches source files and rebuilds on change.

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

```bash
flox activate -- make seed
```

Requires `oras`, `syft`, and `curl` — all available in the Flox environment.

## Stopping

```bash
flox activate -- make dev-down         # Stop Tilt (keeps cluster running)
flox activate -- make dev-cluster-down # Destroy the cluster and registry
```

## How It Works

- `make dev-cluster-up` runs `talosctl cluster create` with a custom registry-mirror config (`tilt/talos-cluster.yaml`) so pods pull from the host's bridge IP `10.5.0.1:5005`.
- `make dev-up` runs Tilt, which reads `Tiltfile` at the repo root. The Tiltfile generates the `ocidex-secrets` Secret from the local `.env` file (kustomize's secretGenerator cannot read files outside the kustomization root), builds the images, and applies `k8s/overlays/dev`.
- The dev overlay scales all Deployments to 1 replica, uses `IfNotPresent` pull policy, and sets `NATS_STREAM_REPLICAS=1`.

## Troubleshooting

**Pods stuck in `ImagePullBackOff`:** Confirm the image was pushed to `localhost:5005`. Check `tilt` logs in the Tilt UI. Verify the cluster is running: `talosctl cluster show`.

**Port-forward drops:** Re-run `make dev-up` — Tilt automatically re-establishes port-forwards on restart.

**Secret not found:** Check that `.env` exists at the repo root with at minimum `DATABASE_URL`, `NATS_URL`, and `SESSION_SECRET`. See `.env.example`.

**NATS issues in dev:** The dev overlay sets `NATS_STREAM_REPLICAS=1` (single-node NATS). If you recreate the cluster, NATS stream state is lost — this is expected for dev.
