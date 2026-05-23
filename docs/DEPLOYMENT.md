# Production Deployment

Target: **https://ocidex.app** on the homelab Pi Talos cluster, in distributed
mode (API + `scanner-worker` + `enrichment-worker` + NATS JetStream + Postgres +
web), reconciled from Git by Flux, served through the existing
`cloudflare-gateway` Cloudflare Tunnel.

For development/local workflows see [`docs/CONFIGURATION.md`](CONFIGURATION.md)
and the dev-cluster targets in the root `Makefile`
(`make dev-cluster-up`, `make dev-up`). For runtime architecture see
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md).

The complete env-var reference (every variable, default, and effect) lives in
[`docs/CONFIGURATION.md`](CONFIGURATION.md). **Source of truth for env tag
names: [`internal/config/config.go`](../internal/config/config.go).** This
document narrows that reference to the **production subset** and the end-to-end
walkthrough connecting it to the cluster.

---

## Topology

```
          ┌─ HTTPRoute (ocidex.app, cloudflare-gateway) ─┐
          ▼                                              │
   ┌────────────┐    ┌───────────┐    ┌────────────────┐ │
   │ ocidex-web │    │ ocidex-api│◀───┤ ocidex-secrets │ │  Secret
   │  (Caddy)   │───▶│ (Deploy×2)│    └────────────────┘ │  (SOPS,
   └────────────┘    └─────┬─────┘                       │   homelab)
                           │ NATS JetStream              │
                ┌──────────┴──────────┐                  │
                ▼                     ▼                  │
        ┌───────────────┐    ┌─────────────────┐         │
        │scanner-worker │    │enrichment-worker│         │
        └───────┬───────┘    └────────┬────────┘         │
                │                     │                  │
                └──────────┬──────────┘                  │
                           ▼                             │
                    ┌─────────────┐                      │
                    │  postgres   │◀── goose-migrate Job │
                    │ StatefulSet │     (runs on apply)  │
                    └─────────────┘                      │
```

All pods live in the `ocidex` namespace.

---

## Env-var contract

Three classes of source:

- **Secret** — supplied by `ocidex-secrets` (one Kubernetes `Secret`,
  SOPS-encrypted in the homelab repo). Wired into every workload via
  `envFrom: secretRef: ocidex-secrets` in `k8s/base/*.yaml`.
- **Deployment env** — set per-workload in `k8s/overlays/prod/` via patches.
- **Default** — omitted; relies on `envDefault` in `internal/config/config.go`.

### API (`ocidex-api`, `replicas: 2`)

| Variable | Source | Production value |
|---|---|---|
| `DATABASE_URL` | Secret | `postgres://ocidex:<password>@postgres:5432/ocidex?sslmode=disable` |
| `GITHUB_CLIENT_ID` | Secret | from OAuth App (`0my.9`) |
| `GITHUB_CLIENT_SECRET` | Secret | from OAuth App (`0my.9`) |
| `SESSION_SECRET` | Secret | `openssl rand -hex 32` (`0my.10`) |
| `GITHUB_REDIRECT_URL` | Deployment env | `https://ocidex.app/auth/callback` |
| `OCIDEX_MODE` | Deployment env | `distributed` |
| `NATS_URL` | Deployment env | `nats://nats:4222` |
| `NATS_STREAM_REPLICAS` | Deployment env | `3` |
| `ENVIRONMENT` | Deployment env | `production` |
| `LOG_LEVEL` | Deployment env | `info` |
| `PORT` | Deployment env | `8080` |
| `FRONTEND_URL` | Deployment env | `https://ocidex.app` |
| `CORS_ALLOWED_ORIGINS` | Deployment env | `https://ocidex.app` |
| `API_BASE_URL` | Deployment env | `https://ocidex.app` |
| `SCANNER_ENABLED` | Deployment env | `true` *(registry poller side only; scan work runs in `scanner-worker`)* |
| `REGISTRY_POLLER_ENABLED` | Deployment env | `true` |
| `SESSION_MAX_AGE_DAYS` | Default | `7` |
| `AUDIT_LOG_ENABLED` | Default | `true` |

Source of truth: [`internal/config/config.go`](../internal/config/config.go).

### `scanner-worker` & `enrichment-worker` (`replicas: 1` each)

| Variable | Source | Production value |
|---|---|---|
| `DATABASE_URL` | Secret | same as API |
| `OCIDEX_MODE` | Deployment env | `distributed` |
| `NATS_URL` | Deployment env | `nats://nats:4222` |
| `NATS_STREAM_REPLICAS` | Deployment env | `3` |
| `DATABASE_MAX_CONNECTIONS` | Deployment env | `3` |
| `LOG_LEVEL` | Deployment env | `info` |
| `ENVIRONMENT` | Deployment env | `production` |
| `SCANNER_WORKERS` *(scanner only)* | Default | `2` |
| `ENRICHMENT_WORKERS` *(enrichment only)* | Default | `2` |

Workers do **not** need the OAuth or session vars and do not start the HTTP
server. See [`ocidex-mf3`](https://github.com/pfenerty/ocidex) for the open bug
that workers currently still require those vars at startup — until it is fixed,
include them via `envFrom` too.

### `goose-migrate` Job (one-shot, on every apply)

| Variable | Source | Production value |
|---|---|---|
| `DATABASE_URL` | Secret | same as API |

### `postgres` StatefulSet

| Variable | Source | Production value |
|---|---|---|
| `POSTGRES_USER` | Deployment env | `ocidex` |
| `POSTGRES_DB` | Deployment env | `ocidex` |
| `POSTGRES_PASSWORD` | Secret | `openssl rand -base64 24` (`0my.10`) |
| `PGDATA` | Deployment env | `/var/lib/postgresql/data/pgdata` |

### `ocidex-web` (Caddy, static SolidJS bundle)

No application env vars. The image bakes `web/dist/` + a `Caddyfile` that
reverse-proxies `/api/*` and `/auth/*` to `ocidex-api:8080`.

---

## Secret material

All five sensitive values live in **one** `Secret`, `ocidex-secrets`, in the
`ocidex` namespace. The Secret is authored as `secret.sops.yaml` in
`homelab/talos-cluster/flux/apps/ocidex/`, SOPS-encrypted, and applied by Flux.
It is **not** in this repo; `k8s/base/*.yaml` only references it via `envFrom`.

| Key | How to generate / obtain |
|---|---|
| `SESSION_SECRET` | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | `openssl rand -base64 24` (no shell-special chars) |
| `DATABASE_URL` | Composed: `postgres://ocidex:<POSTGRES_PASSWORD>@postgres:5432/ocidex?sslmode=disable` |
| `GITHUB_CLIENT_ID` | GitHub OAuth App (see `0my.9`) |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App (see `0my.9`) |

**Never** commit raw values. Run `openssl` locally, paste into the SOPS
plaintext, encrypt, commit only the encrypted file.

---

## Deploy from scratch

Each step links to the beads issue that owns it. Steps 1, 3, and 5 are merged.

1. **Multi-arch images on GHCR** (`ocidex-0my.1`, merged).
   GitHub Actions publishes
   `ghcr.io/pfenerty/ocidex-{api,scanner-worker,enrichment-worker,web,migrate}:<tag>`
   for `linux/amd64,linux/arm64` on every `main` push and tag.

2. **Create the GitHub OAuth App** (`ocidex-0my.9`).
   In GitHub → Settings → Developer settings → OAuth Apps → New OAuth App:
     - Application name: `OCIDex (homelab)`
     - Homepage URL: `https://ocidex.app`
     - Authorization callback URL: `https://ocidex.app/auth/callback`
   Record the Client ID; generate a Client Secret. Hand both to step 6.

3. **Generate the secret values** (`ocidex-0my.10`).
     ```
     openssl rand -hex 32       # SESSION_SECRET
     openssl rand -base64 24    # POSTGRES_PASSWORD
     ```
   Compose `DATABASE_URL` from the password as shown above.

4. **Author `k8s/overlays/prod/`** (`ocidex-0my.6`).
   Mirrors `k8s/overlays/dev/`. Includes:
     - `kustomization.yaml` referencing `../../base`, with `images:` pinning
       every deployable image to its `ghcr.io/pfenerty/ocidex-*` `newName` and a
       commit-SHA `newTag` (image automation later); `imagePullPolicy:
       IfNotPresent`.
     - `patches/replicas.yaml` (api=2, scanner/enrichment workers=1, nats=3).
     - `patches/resources.yaml` (Pi-appropriate: api 500m/512Mi,
       workers 500m/512Mi, postgres 500m/1Gi, web 100m/128Mi).
     - `patches/env-prod.yaml` — the **Deployment env** values from the tables
       above (`OCIDEX_MODE`, `GITHUB_REDIRECT_URL`, `FRONTEND_URL`, …).
   Does **not** define `ocidex-secrets`; that comes from step 6.

5. **Build the homelab Flux app** (`ocidex-0my.11`):
   `homelab/talos-cluster/flux/apps/ocidex/` mirroring the `podinfo` layout:
     - `namespace.yaml` (`ocidex`)
     - `kustomization.yaml` (Flux Kustomization) pointing at
       `https://github.com/pfenerty/ocidex//k8s/overlays/prod`
     - `route.yaml` — `HTTPRoute` attached to
       `cloudflare-gateway/cloudflare-gateway`, hostname `ocidex.app`,
       `backendRefs: [{name: ocidex-web, port: 80}]`
     - `secret.sops.yaml` — the `ocidex-secrets` Secret (step 6)
   Wire the new app into `homelab/.../flux/apps/kustomization.yaml`.

6. **SOPS-encrypt the secret** (`ocidex-0my.12`).
   Author `secret.sops.yaml` with the five keys from step 2 and 3, then
   `sops --encrypt --in-place` per the homelab repo's age recipients. Commit
   only the encrypted file.

7. **DNS for `ocidex.app`** (`ocidex-0my.13`).
   `ocidex.app` is in the same Cloudflare account as `pfenerty.com`, so the
   existing tunnel and edge-TLS configuration apply. Open question: does the
   cloudflare-gateway controller auto-create the CNAME for any hostname in an
   attached HTTPRoute, or is it manual? Verify by inspecting how
   `podinfo.pfenerty.com` ended up in DNS; if manual, add a CNAME for the apex
   `ocidex.app` (and disable Cloudflare proxy as needed for tunnel use) via the
   Cloudflare dashboard.

8. **Smoke test** (`ocidex-0my.14`).
   - `kubectl -n ocidex get pods` — everything `Running`/`Ready`
   - `curl -fsS https://ocidex.app/health` and `/ready`
   - Browser → `https://ocidex.app` → "Sign in with GitHub" → OAuth round-trip
     lands back on the SPA authenticated
   - Upload a small CycloneDX SBOM via the UI; confirm it lists and you can
     open it

---

## Update procedure

To roll a new image:

1. Push the change to `main`; GHA publishes new `ghcr.io/pfenerty/ocidex-*`
   images tagged with the commit SHA.
2. In `k8s/overlays/prod/kustomization.yaml`, bump `images:` `newTag` for the
   affected components to the new SHA.
3. Commit and push the ocidex repo.
4. Flux reconciles the overlay (default interval ~5 min) and rolls each
   `Deployment`. Watch with `kubectl -n ocidex rollout status deploy/ocidex-api`.

Flux image automation (`ImagePolicy` + `ImageUpdateAutomation`) is deferred; do
it later once tag policies are stable.

## Rollback

`git revert` the image-tag bump commit in this repo (or the offending change in
`homelab` if a manifest changed). Push; Flux reconciles back to the prior tag.
Postgres data persists in the StatefulSet PVC across rollbacks.

---

## Troubleshooting

| Symptom | First thing to check |
|---|---|
| Pods stuck `CreateContainerConfigError` | `kubectl -n ocidex describe pod …` — usually `ocidex-secrets` missing or misnamed; verify the homelab Flux app reconciled the Secret. |
| API pod `CrashLoopBackOff` immediately at startup | `kubectl -n ocidex logs deploy/ocidex-api` — missing required env (`DATABASE_URL`, OAuth vars, `SESSION_SECRET`) or `OCIDEX_MODE` not `embedded`/`distributed`. |
| OAuth login returns 400 `redirect_uri_mismatch` | `GITHUB_REDIRECT_URL` env in `k8s/overlays/prod` does not exactly match the OAuth App's "Authorization callback URL". |
| `goose-migrate` Job fails | `kubectl -n ocidex logs job/goose-migrate` — usually `DATABASE_URL` shape, Postgres not yet `Ready`, or pgcrypto extension permission. |
| `https://ocidex.app` returns 404 from Cloudflare | HTTPRoute hostname / `parentRefs` mismatch; `kubectl -n ocidex get httproute -o yaml`. Verify the cloudflare-gateway controller logs accepted the route. |
| API pods `Ready` but `/health` 502 via tunnel | `ocidex-web` Service selector vs Deployment labels, or HTTPRoute backendRef name/port wrong (should be `ocidex-web:80`). |
| Postgres pod restart loops | PVC permissions on `/var/lib/postgresql/data/pgdata`; check `local-path-provisioner` events. |
