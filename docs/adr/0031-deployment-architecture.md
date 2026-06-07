# ADR-031: Deployment Architecture — Helm-first, Kustomize for dev

**Status:** Accepted
**Date:** 2026-06-07
**Epic:** ocidex-8ik — 1.1b Helm deployment + CI/CD pipeline

---

## Context

The existing deployment model uses two Kustomize overlays (dev and prod). As the project matures, several gaps need addressing:

- KEDA ScaledObjects for workers live in an external homelab repo rather than with the code they scale
- No monitoring, Gateway API, or network policy manifests exist in this repo
- The operator has no Docker image stage
- The production install model is inconsistent with how other homelab apps are deployed

## Decision

**Helm as the primary install model** for homelab and external deployments. Kustomize is retained for local dev (Tilt uses `k8s/overlays/dev/`) and is not replaced.

### Tooling

| Context | Tool | Why |
|---------|------|-----|
| Local dev (Tilt) | Kustomize (`k8s/overlays/dev/`) | Already works; no reason to change |
| Homelab/prod install | Helm (`charts/ocidex/`) | Consistent with other homelab apps; OCI chart publishing via GHCR |
| Operator install | Helm (`charts/ocidex-operator/`) | Already scaffolded in ocidex-01v.7 |
| CI artifacts | OCI Helm charts on GHCR | `helm push oci://ghcr.io/pfenerty/charts` |

### KRO (deferred)

KRO v0.3.x is alpha, requires its own controller, and has no production track record. Revisit when it reaches v1.0. The OCIDex operator itself is a candidate to eventually expose an `OCIDexStack` CRD that serves the same composition purpose without an additional dependency.

### Dependency / boundary model

| Layer | What | Managed by |
|-------|------|------------|
| Platform | CNPG, KEDA operator, Prometheus Operator, Cilium, Gateway API CRDs | External — NOT in this repo |
| Application | API, workers, NATS, web, migrate Job | `charts/ocidex/` (Helm) |
| App integrations | KEDA ScaledObjects, PodMonitors, HTTPRoutes, NetworkPolicies | `charts/ocidex/` via optional values flags |
| Operator | OCIDex operator + CRDs | `charts/ocidex-operator/` (Helm) |
| Database | PostgreSQL (CNPG) | External — `DATABASE_URL` injected as external Secret |

PostgreSQL is a platform concern. No DB manifests belong in this repo.

### Optional integrations

All optional integrations are gated by `values.yaml` feature flags and disabled by default:

| Flag | Resources created |
|------|-------------------|
| `keda.enabled` | `ScaledObject` for `ocidex-scanner-worker` |
| `monitoring.enabled` | `PodMonitor` for each workload |
| `gatewayApi.enabled` | `HTTPRoute` for api and web |
| `cilium.enabled` | `CiliumNetworkPolicy` isolating app ↔ NATS |

### CI/CD lifecycle

| Event | What happens |
|-------|-------------|
| Push to `main` | Build 5 images tagged `main` + `sha-<short>` → publish Helm charts with `appVersion=sha-<short>` → homelab dev HelmRelease auto-upgrades |
| Push tag `v*.*.*` | Build 5 images with semver tags → publish Helm charts with semver `appVersion` → git-cliff release notes → GitHub Release |

Image tag binding: `values.yaml` sets `image.tag: ""`. Templates resolve to `{{ .Values.image.tag | default .Chart.AppVersion }}`. When a chart is packaged with `--app-version sha-abc1234` (dev) or `--app-version v1.2.3` (release), the default image tags match the images built in the same pipeline run.

## Consequences

- Homelab installs become `helm upgrade --install ocidex oci://ghcr.io/pfenerty/charts/ocidex --version sha-<commit>`
- KEDA ScaledObjects move into this repo (as chart templates), eliminating the split between app code and scaling config
- New integrations (monitoring, Gateway, Cilium) can be enabled per-cluster with `--set <flag>.enabled=true`
- `k8s/overlays/dev/` and Tiltfile remain unchanged
- The existing OCI manifests Flux job in `images.yml` is kept during the homelab migration period; removed once the homelab switches to HelmRelease

## Key files

- `charts/ocidex/` — application Helm chart
- `charts/ocidex-operator/` — operator Helm chart (ocidex-01v.7)
- `.github/workflows/images.yml` — add operator, add Helm chart publish
- `.github/workflows/release.yml` — add operator, add Helm chart publish
- `docker/Dockerfile` — add operator build + stage
