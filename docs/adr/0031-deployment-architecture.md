# ADR-031: Deployment Architecture — Helm-first

**Status:** Accepted (amended 2026-08-10)
**Date:** 2026-06-07
**Epic:** ocidex-8ik — 1.1b Helm deployment + CI/CD pipeline

> **Amended 2026-08-10 (ocidex-b38j).** Two claims below are no longer true.
> (1) The "Kustomize retained for local dev" half was reversed in `e1bf40f`: `k8s/` was
> deleted and Tilt now renders `charts/ocidex` with `tilt/values-dev.yaml` (`ocidex-1bbp`).
> Every `k8s/overlays/dev/` reference below is historical — the path does not exist.
> (2) CI never landed on GitHub Actions. It is Tekton Pipelines-as-Code; chart publishing
> lives in `.tektonic/jobs/helm-publish/` and `.tektonic/jobs/helm-release/`, not
> `.github/workflows/`. The Helm-first decision itself stands — deployment is Helm-only.

---

## Context

The existing deployment model uses two Kustomize overlays (dev and prod). As the project matures, several gaps need addressing:

- KEDA ScaledObjects for workers live in an external homelab repo rather than with the code they scale
- No monitoring, Gateway API, or network policy manifests exist in this repo
- The operator has no Docker image stage
- The production install model is inconsistent with how other homelab apps are deployed

## Decision

**Helm as the primary install model** for homelab and external deployments. ~~Kustomize is retained for local dev (Tilt uses `k8s/overlays/dev/`) and is not replaced.~~ *(Amended — see the note above: Kustomize was dropped entirely; Tilt renders `charts/ocidex` with `tilt/values-dev.yaml`.)*

### Tooling

| Context | Tool | Why |
|---------|------|-----|
| Local dev (Tilt) | Helm (`charts/ocidex/` + `tilt/values-dev.yaml`) | Amended 2026-08-10 — originally Kustomize (`k8s/overlays/dev/`); same chart as prod means the dev loop exercises what ships |
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
- ~~`k8s/overlays/dev/` and Tiltfile remain unchanged~~ — amended: `k8s/` was deleted instead (`e1bf40f`), and the Tiltfile was rewritten to render `charts/ocidex` with `tilt/values-dev.yaml`
- ~~The existing OCI manifests Flux job in `images.yml` is kept during the homelab migration period; removed once the homelab switches to HelmRelease~~ — amended: the migration completed. The homelab consumes the chart via HelmRelease; see [`docs/DEPLOYMENT.md`](../DEPLOYMENT.md)

## Key files

- `charts/ocidex/` — application Helm chart
- `charts/ocidex-operator/` — operator Helm chart (ocidex-01v.7)
- ~~`.github/workflows/images.yml`~~ → `.tektonic/jobs/helm-publish/` — add operator, add Helm chart publish (push pipeline)
- ~~`.github/workflows/release.yml`~~ → `.tektonic/jobs/helm-release/` — add operator, add Helm chart publish (tag pipeline)
- `docker/Dockerfile` — add operator build + stage
