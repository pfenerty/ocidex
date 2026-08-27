# Cluster Deployment

Target: **https://ocidex.app** on the homelab Pi Talos cluster, in distributed
mode (API + `scanner-worker` + the per-enricher workers + `vuln-worker` + NATS
JetStream + web), installed from the `charts/ocidex` Helm chart, reconciled from
Git by Flux, served through the existing `cloudflare-gateway` Cloudflare Tunnel.

Deployment is Helm-only. There is no kustomize base or overlay in this repo —
`k8s/` was removed once the chart landed (ADR-031), and the local Tilt loop
renders the same chart with `tilt/values-dev.yaml`.

For development/local workflows see [`docs/K8S_DEV.md`](K8S_DEV.md) and the
dev-cluster targets in the root `Makefile` (`make dev-cluster-up`, `make dev-up`).
For runtime architecture see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md).

The complete env-var reference (every variable, default, and effect) lives in
[`docs/CONFIGURATION.md`](CONFIGURATION.md). **Source of truth for env tag
names: [`internal/config/config.go`](../internal/config/config.go).** This
document narrows that reference to the **cluster subset** and the end-to-end
walkthrough connecting it to the cluster.

---

## Topology

The chart owns everything inside the dashed box. The Secret, the HTTPRoute, and
the database are pre-existing inputs supplied by the homelab repo — the chart
renders none of them.

```
   ┌─ HTTPRoute (ocidex.app → cloudflare-gateway) ──┐   homelab repo
   │  /api,/auth,/health,/ready ─┐                  │
   ▼  everything else            ▼                  │
╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
┆  ┌──────────────┐   ┌──────────────┐                          ┆
┆  │ ocidex-dev-  │   │ ocidex-dev-  │◀── ocidex-secrets  ──────┼── Secret
┆  │ web (nginx)  │   │ api          │    (envFrom, every pod)  ┆   (SOPS,
┆  └──────────────┘   └──────┬───────┘                          ┆   homelab)
┆                            │ NATS JetStream                   ┆
┆                 ┌──────────┴──────────┐                       ┆
┆                 ▼                     ▼                       ┆
┆   ┌────────────────────┐   ┌─────────────────────┐            ┆
┆   │ scanner-worker     │   │ enricher workers    │            ┆
┆   │                    │   │ (oci-metadata, git, │            ┆
┆   │                    │   │  user, provenance)  │            ┆
┆   └─────────┬──────────┘   └──────────┬──────────┘            ┆
┆             │      ┌─────────────┐    │                       ┆
┆             │      │ vuln-worker │    │  ocidex-dev-migrate   ┆
┆             │      └──────┬──────┘    │  Job (Helm pre-       ┆
┆             └─────────────┼───────────┘  install/upgrade hook)┆
╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
                            ▼
                  ┌─────────────────────┐
                  │ CloudNativePG       │  external to the chart
                  │ Cluster "ocidex-pg" │  (homelab repo)
                  │ svc ocidex-pg-rw    │
                  └─────────────────────┘
```

All application pods live in the `ocidex-dev` namespace, from a Helm release
named `ocidex-dev`. The release name is the resource-name prefix
(`ocidex.fullname`), which is why every Service and Deployment reads
`ocidex-dev-*`. The operator, when installed, is a **separate** chart and release
(`ocidex-operator-dev` in namespace `ocidex-operator-dev`, with
`watchNamespace: ocidex-dev`).

---

## Env-var contract

Three classes of source:

- **Secret** — supplied by `ocidex-secrets` (one Kubernetes `Secret`,
  SOPS-encrypted in the homelab repo, named by `existingSecret` in values).
  Wired into every workload via `envFrom: secretRef:` by the chart templates.
- **Chart values** — set per-workload under `api.env.*`, `scannerWorker.env.*`,
  `enricherWorkerDefaults.env.*` and `vulnWorker.env.*` in
  [`charts/ocidex/values.yaml`](../charts/ocidex/values.yaml), overridable from
  the HelmRelease `values:` block.
- **Default** — omitted from the chart; relies on `envDefault` in
  `internal/config/config.go`.

The values below are the chart defaults as overridden by the homelab
HelmRelease, i.e. what is actually running. `charts/ocidex/values.yaml` is the
authoritative default set.

### API (`ocidex-dev-api`, `api.replicas: 1`)

| Variable | Source | Deployed value |
|---|---|---|
| `DATABASE_URL` | Secret | `host=ocidex-pg-rw port=5432 dbname=ocidex user=ocidex password=<password> sslmode=disable` |
| `GITHUB_CLIENT_ID` | Secret | from the OAuth App |
| `GITHUB_CLIENT_SECRET` | Secret | from the OAuth App |
| `SESSION_SECRET` | Secret | `openssl rand -hex 32` |
| `PORT` | chart (fixed) | `8080` |
| `NATS_URL` | chart (fixed) | `nats://ocidex-dev-nats:4222` |
| `NATS_STREAM_REPLICAS` | `api.env.natsStreamReplicas` | `1` |
| `ENVIRONMENT` | `api.env.environment` | `development` |
| `LOG_LEVEL` | `api.env.logLevel` | `info` |
| `FRONTEND_URL` | `api.env.frontendUrl` | `https://ocidex.app` |
| `CORS_ALLOWED_ORIGINS` | `api.env.corsAllowedOrigins` | `https://ocidex.app` |
| `API_BASE_URL` | `api.env.apiBaseUrl` | unset |
| `GITHUB_REDIRECT_URL` | `api.env.githubRedirectUrl` | `https://ocidex.app/auth/callback` |
| `SCANNER_ENABLED` | `api.env.scannerEnabled` | `true` *(registry poller side only; scan work runs in `scanner-worker`)* |
| `REGISTRY_POLLER_ENABLED` | `api.env.registryPollerEnabled` | `true` |
| `SESSION_MAX_AGE_DAYS` | Default | `7` |
| `AUDIT_LOG_ENABLED` | Default | `true` |

`NATS_URL` is templated from `ocidex.fullname`, so it tracks the release name —
a release named something other than `ocidex-dev` gets a correspondingly
different host. `FRONTEND_URL`, `CORS_ALLOWED_ORIGINS`, `API_BASE_URL` and
`GITHUB_REDIRECT_URL` are emitted **only when non-empty**; leaving them at the
`""` default omits the env var entirely rather than setting it blank.

Source of truth: [`internal/config/config.go`](../internal/config/config.go).

### `scanner-worker` (`scannerWorker.replicas: 1`)

| Variable | Source | Deployed value |
|---|---|---|
| `DATABASE_URL` | Secret | same as API |
| `NATS_URL` | chart (fixed) | `nats://ocidex-dev-nats:4222` |
| `NATS_STREAM_REPLICAS` | `scannerWorker.env.natsStreamReplicas` | `1` |
| `DATABASE_MAX_CONNECTIONS` | `scannerWorker.env.databaseMaxConnections` | `3` |
| `SCANNER_MAX_CONCURRENCY` | `scannerWorker.env.maxConcurrency` | `1` |
| `ENVIRONMENT` | `scannerWorker.env.environment` | `development` |
| `LOG_LEVEL` | `scannerWorker.env.logLevel` | `info` |

`scannerWorker.replicas` is ignored when `keda.enabled=true` — the ScaledObject
owns the replica count and the Deployment renders without one.

### Per-enricher workers (`enricherWorkerDefaults.replicas`, one Deployment each)

One Deployment per entry in `enricherWorkers` (ADR-033): `oci-metadata-worker`,
`git-worker`, `user-enricher-worker`, `provenance-worker`. They share the sizing
and env under `enricherWorkerDefaults`, and an `enricherWorkers` entry may carry its
own `resources`, or its own keys under `env`, to override the shared values for that
worker alone.

`provenance-worker` does exactly that (128Mi request / 512Mi limit): it is the only
enricher linking cosign + sigstore-go (ADR-037) and pulling signature/attestation
layers from the registry, and it OOMKilled at the shared 128Mi limit while the other
three measure 9-16Mi.

| Variable | Source | Deployed value |
|---|---|---|
| `DATABASE_URL` | Secret | same as API |
| `NATS_URL` | chart (fixed) | `nats://ocidex-dev-nats:4222` |
| `NATS_STREAM_REPLICAS` | `enricherWorkerDefaults.env.natsStreamReplicas` | `1` |
| `DATABASE_MAX_CONNECTIONS` | `enricherWorkerDefaults.env.databaseMaxConnections` | `3` |
| `ENRICHMENT_MAX_CONCURRENCY` | `enricherWorkerDefaults.env.maxConcurrency` | `10` (`provenance-worker`: `2`) |
| `ENVIRONMENT` | `enricherWorkerDefaults.env.environment` | `development` |
| `LOG_LEVEL` | `enricherWorkerDefaults.env.logLevel` | `info` |
| `ENRICHMENT_WORKERS` | Default | `2` |
| `PROVENANCE_MAX_LAYER_BYTES` | Default | `16777216` (16MiB; `provenance-worker` only) |

Workers do **not** need the OAuth or session vars and do not start the HTTP API;
they receive them anyway because `envFrom` pulls the whole Secret, which is
harmless. Each worker does serve `/healthz` and `/readyz` on port 9090 for the
kubelet probes.

### `vuln-worker` (`vulnWorker.enabled: true`, `replicas: 1`)

Scheduled OSV.dev refresh of the package-keyed vulnerability store. Talks only
to Postgres and OSV.dev — no NATS, no KEDA. A Postgres advisory lock makes >1
replica safe, but 1 is sufficient.

| Variable | Source | Deployed value |
|---|---|---|
| `DATABASE_URL` | Secret | same as API |
| `DATABASE_MAX_CONNECTIONS` | `vulnWorker.env.databaseMaxConnections` | `3` |
| `ENVIRONMENT` | `vulnWorker.env.environment` | `development` |
| `LOG_LEVEL` | `vulnWorker.env.logLevel` | `info` |
| `VULN_REFRESH_ENABLED` | `vulnWorker.env.refreshEnabled` | `true` |
| `VULN_REFRESH_INTERVAL` | `vulnWorker.env.refreshInterval` | `6h` |
| `OSV_BASE_URL` | `vulnWorker.env.osvBaseURL` | `https://api.osv.dev` |
| `OSV_TIMEOUT` | `vulnWorker.env.osvTimeout` | `30s` |
| `OSV_BATCH_SIZE` | `vulnWorker.env.osvBatchSize` | `1000` |

### `ocidex-dev-migrate` Job (Helm hook, on every install and upgrade)

Rendered by `charts/ocidex/templates/job-migrate.yaml` as a
`pre-install,pre-upgrade` hook with weight `-1`, so it completes before any
Deployment is updated. Runs the API image with
`command: ["/ocidex", "migrate", "up"]` — the API binary embeds the migration
files and the goose runtime, so no separate image is needed. The Job name
carries the release revision (`ocidex-dev-migrate-<revision>`).

| Variable | Source | Deployed value |
|---|---|---|
| `DATABASE_URL` | Secret | same as API |
| `NATS_URL` | chart (fixed) | `nats://ocidex-dev-nats:4222` |
| `OCIDEX_MIGRATE_SKIP_OWNERSHIP_CHECK` | *(optional, not set by the chart)* | unset |

Set `migrate.enabled=false` only if you apply migrations out of band.

`migrate up` runs an ownership preflight before goose touches the schema: if any
`public`-schema object is owned by a role other than the app role, the Job fails
with the exact `ALTER ... OWNER TO` statements to run as a superuser. That state
only arises from hand-run DDL on a deployed database — see
[DEVELOPMENT.md § Database Ownership](DEVELOPMENT.md#database-ownership). Job
pods are reaped a few minutes after failure, so if the logs are already gone,
`ocidex migrate audit` in a throwaway pod reproduces the check read-only.

### Database (external CloudNativePG)

The chart renders **no** database (ADR-031: the database is a platform concern,
not an application one). Postgres is a CloudNativePG `Cluster` named `ocidex-pg`
in the `ocidex-dev` namespace, defined in the homelab repo at
`talos-cluster/flux/apps/ocidex/dev/infra/postgres.yaml`. The app reaches it
through CNPG's read-write Service, `ocidex-pg-rw:5432`.

The only coupling between the app and the database is the `DATABASE_URL` key in
`ocidex-secrets`. Nothing in the chart reads `POSTGRES_USER`, `POSTGRES_DB` or
`POSTGRES_PASSWORD`.

For backup, failover and version-upgrade procedures see
[`docs/OPERATIONS.md`](OPERATIONS.md).

### `ocidex-dev-web` (nginx, static SolidJS bundle)

No application env vars. The image (`cgr.dev/chainguard/nginx`) bakes
`web/dist/` + `web/nginx.conf`, which serves static assets with an
`index.html` SPA fallback and **nothing else** — it contains no reverse proxy.

`/api`, `/auth`, `/health` and `/ready` must therefore be routed to the API by
something in front of it. With `gatewayApi.enabled=true` the chart's own
`ocidex-web` HTTPRoute (`charts/ocidex/templates/httproutes.yaml`) does this,
listing them ahead of the `/` catch-all. The homelab deployment instead runs
with `gatewayApi.enabled=false` and supplies an equivalent hand-written
HTTPRoute from the homelab repo (see "Deploy from scratch" step 6). Either way,
that routing is what gives the SPA a same-origin API; without it, a deployment
must build the frontend with `VITE_API_URL` set to the API's origin and list the
frontend origin in `api.env.corsAllowedOrigins`.

nginx runs as UID 65532 and listens on **8080**; the Service maps 80 → 8080.
Under `docker-compose`, which has no L7 router, `web/nginx.compose.conf` is
bind-mounted into `/etc/nginx/ocidex.d/` to reinstate the four proxy rules.

---

## Secret material

All sensitive values live in **one** `Secret`, `ocidex-secrets`, in the
`ocidex-dev` namespace, named by `existingSecret` in the chart values. It is
authored as `secrets.enc.yaml` in
`homelab/talos-cluster/flux/apps/ocidex/dev/main/`, SOPS-encrypted, and applied
by Flux. It is **not** in this repo; the chart only references it via `envFrom`.
`secrets.template.yaml` beside it documents the shape and the `sops` invocation.

| Key | How to generate / obtain | Read by |
|---|---|---|
| `DATABASE_URL` | Composed from the CNPG service and password (see below) | every workload |
| `SESSION_SECRET` | `openssl rand -hex 32` | API |
| `GITHUB_CLIENT_ID` | GitHub OAuth App | API |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App | API |
| `POSTGRES_USER` / `POSTGRES_DB` | `ocidex` / `ocidex` | nothing — see below |
| `POSTGRES_PASSWORD` | `openssl rand -base64 24` (no shell-special chars) | nothing — see below |

`DATABASE_URL` is a libpq **keyword DSN**, not a URL:

```
host=ocidex-pg-rw port=5432 dbname=ocidex user=ocidex password=<POSTGRES_PASSWORD> sslmode=disable
```

The `POSTGRES_*` keys are vestigial from the pre-CNPG StatefulSet — no chart
template and no binary reads them — but do **not** delete them. The homelab
`postgres-app-secret.template.yaml` extracts `POSTGRES_PASSWORD` from this
Secret to build the CNPG `ocidex-pg-app` bootstrap Secret, so the two stay in
sync only because both derive from this one value.

**Never** commit raw values. Run `openssl` locally, paste into the SOPS
plaintext, encrypt, commit only the encrypted file.

---

## Deploy from scratch

Steps 1–3 are prerequisites; 4–7 are the install. Everything from step 4 onward
lives in the homelab repo, under
`talos-cluster/flux/apps/ocidex/dev/{infra,main,operator,registries}/`.

1. **Multi-arch images and charts on GHCR** (CI, already running).
   The Tekton push pipeline publishes
   `ghcr.io/pfenerty/ocidex-{api,scanner-worker,oci-metadata-worker,git-worker,user-enricher-worker,provenance-worker,vuln-worker,web,operator}:<tag>`
   for `linux/amd64,linux/arm64`, then the `helm-publish` task packages and
   pushes `charts/ocidex` and `charts/ocidex-operator` to
   `oci://ghcr.io/pfenerty/charts`. Migrations run from the API image.

2. **Create the GitHub OAuth App.**
   In GitHub → Settings → Developer settings → OAuth Apps → New OAuth App:
     - Application name: `OCIDex (homelab)`
     - Homepage URL: `https://ocidex.app`
     - Authorization callback URL: `https://ocidex.app/auth/callback`
   Record the Client ID; generate a Client Secret. Hand both to step 5.

3. **Generate the secret values.**
     ```
     openssl rand -hex 32       # SESSION_SECRET
     openssl rand -base64 24    # POSTGRES_PASSWORD
     ```
   Compose `DATABASE_URL` from the password as shown above.

4. **Namespace and database** (`dev/infra/`).
     - `namespace.yaml` — `ocidex-dev`.
     - `postgres.yaml` — CNPG `Cluster` `ocidex-pg`, 1 instance, `local-path`
       storage, bootstrapping from the `ocidex-pg-app` Secret.
     - `postgres-app-secret.enc.yaml` — the CNPG bootstrap Secret
       (`username`/`password` only; CNPG accepts exactly those two keys),
       derived from `POSTGRES_PASSWORD` per the template's header comment.

5. **SOPS-encrypt `ocidex-secrets`** (`dev/main/secrets.enc.yaml`).
   Copy `secrets.template.yaml`, fill in the keys from steps 2–3, then
   `sops -e -i` with the homelab repo's age recipients. Commit only the
   encrypted file.

6. **Chart source and release** (`dev/main/`).
     - `helmrepository.yaml` — a Flux `HelmRepository` of `type: oci` pointing at
       `oci://ghcr.io/pfenerty/charts`, interval `5m`.
     - `helmrelease.yaml` — `HelmRelease` `ocidex-dev` in `flux-system` with
       `targetNamespace: ocidex-dev`, `chart: ocidex`,
       `version: ">=0.0.0-0"`, and the values that differ from chart defaults:
       ```yaml
       existingSecret: ocidex-secrets
       nats:
         storage:
           storageClass: local-path
       gatewayApi: { enabled: false }
       keda: { enabled: false }
       monitoring: { enabled: false }
       api:
         env:
           environment: development
           frontendUrl: "https://ocidex.app"
           githubRedirectUrl: "https://ocidex.app/auth/callback"
           corsAllowedOrigins: "https://ocidex.app"
       enricherWorkerDefaults:
         replicas: 1
       ```
       Deliberately **no** `image.tag` override — see "Update procedure".
     - `httproute.yaml` — `HTTPRoute` in `ocidex-dev` attached to
       `cloudflare-gateway/cloudflare-gateway`, hostname `ocidex.app`, with
       `/api` + `/auth` routed to `ocidex-dev-api:80` **ahead of** the `/`
       catch-all to `ocidex-dev-web:80`. Rule order matters: controllers that
       flatten HTTPRoutes into first-match-wins lists (Cloudflare Tunnel does)
       will otherwise swallow `/api` into the SPA.

   On a cluster without Flux, the same install is:
   ```bash
   helm upgrade --install ocidex-dev oci://ghcr.io/pfenerty/charts/ocidex \
     --namespace ocidex-dev --create-namespace \
     --version <chart-version> \
     -f values-homelab.yaml
   ```

7. **DNS for `ocidex.app`.**
   `ocidex.app` is in the same Cloudflare account as `pfenerty.com`, so the
   existing tunnel and edge-TLS configuration apply. If the cloudflare-gateway
   controller does not auto-create the CNAME for the hostname on the attached
   HTTPRoute, add a CNAME for the apex `ocidex.app` (and disable Cloudflare
   proxy as needed for tunnel use) via the Cloudflare dashboard.

8. **Smoke test.**
   - `kubectl -n ocidex-dev get pods` — everything `Running`/`Ready`
   - `kubectl -n ocidex-dev get cluster ocidex-pg` — CNPG healthy
   - `flux -n flux-system get helmrelease ocidex-dev` — `Ready=True`, and the
     reported revision matches the newest published chart
   - `curl -fsS https://ocidex.app/health` and `/ready`
   - Browser → `https://ocidex.app` → "Sign in with GitHub" → OAuth round-trip
     lands back on the SPA authenticated
   - Upload a small CycloneDX SBOM via the UI; confirm it lists and you can
     open it

### Operator (optional, separate release)

`charts/ocidex-operator` installs as its own `HelmRelease`
(`dev/operator/helmrelease.yaml`): release `ocidex-operator-dev`, namespace
`ocidex-operator-dev`, `install.crds: CreateReplace`, `watchNamespace:
ocidex-dev`, and `server.url` pointed at
`http://ocidex-dev-api.ocidex-dev.svc.cluster.local`. It needs its own Secret
carrying `OCIDEX_API_KEY`.

### Cluster inventory agent (separate chart, per target cluster)

`charts/ocidex-k8s-agent` reports which images are running in a cluster (ADR-044). It is a
**separate chart, installed once per cluster you want inventoried** — including clusters that
have no OCIDex deployment at all, which is the normal case and the reason it is not a toggle
inside `charts/ocidex`. It needs no database, no NATS and no CRDs; it lists pods and POSTs a
snapshot to the API over HTTP.

Install (repeat per cluster, against that cluster's kubeconfig context):

```bash
# 1. Register the cluster in OCIDex (Clusters page in the UI, or the API) and note the
#    returned id.
curl -fsS -X POST https://ocidex.app/api/v1/clusters \
  -H "Authorization: Bearer $OCIDEX_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"prod-eu","namespace_id":"<namespace-uuid>"}'

# 2. Create the API key Secret in the target cluster. read-write scope, owned by a user
#    who owns the namespace the cluster is registered under (ADR-044 K8).
kubectl create namespace ocidex-agent
kubectl -n ocidex-agent create secret generic ocidex-k8s-agent-secrets \
  --from-literal=OCIDEX_API_KEY="$OCIDEX_API_KEY"

# 3. Install the chart.
helm install ocidex-k8s-agent oci://ghcr.io/pfenerty/charts/ocidex-k8s-agent \
  -n ocidex-agent \
  --set server.url=https://ocidex.app \
  --set cluster.id=<cluster-uuid>
```

`server.url` is usually cluster-**external** here, unlike every other chart in this repo —
the agent reaches OCIDex across clusters, so that URL must be routable from the target
cluster and its TLS chain must validate there.

Verify: `kubectl -n ocidex-agent logs deploy/ocidex-k8s-agent` shows an `inventory reported`
line with `pods`, `workloads`, `unresolvable`, `accepted` and `pruned` counts, and the
cluster's `last_seen_at` advances in OCIDex — the Clusters page shows that timestamp, and the
cluster's own page shows the reported inventory with its SBOM coverage. A cluster that reads
`never reported` there has not been pushed to at all, which is not the same as a cluster
running nothing. A non-zero `unresolvable` count is a real
signal, not noise: those pods' `imageID`s carry no registry-addressable digest (a
dockershim-era node runtime, typically) and their images can never be matched to an SBOM.

What the cluster page then shows, and what to do about each thing it reports, is covered in
[CLUSTER_INVENTORY.md](CLUSTER_INVENTORY.md) — including auto-ingest, which is **on by default**
and queues a scan for every reported image that a registry in the cluster's namespace can serve.

Two operational notes that look like bugs and are not:

- Every push **replaces** the cluster's whole inventory (ADR-044 K7). Narrowing
  `namespaces` therefore *deletes* the dropped namespaces' workloads on the next push.
- Two agents must never report for one `cluster.id`. The Deployment sets `maxSurge: 0` for
  that reason; installing the chart twice against the same id makes the stored inventory
  alternate between the two agents' snapshots.

**One-shot / CronJob mode**: the binary also accepts `--once` (push one snapshot, exit
0/1 — ADR-027). The chart renders the long-lived Deployment only; if you want the CronJob
shape, run the image with `args: ["--once"]` and the same env block.

---

## Update procedure

There is no image-tag bump to make. The chart version *is* the release trigger:

1. Push to `main`. The Tekton push pipeline builds and pushes the images tagged
   `sha-<short>`, then `helm-publish` packages the chart as
   `0.1.0-main.<build-epoch>.<short-sha>` with `appVersion: sha-<short>` and
   pushes it to `oci://ghcr.io/pfenerty/charts`.
2. Flux's `HelmRepository` polls every 5 min; the HelmRelease's
   `version: ">=0.0.0-0"` range selects the newest chart.
3. Because the HelmRelease sets no `image.tag`, the chart's templates fall back
   to `Chart.AppVersion` — so the new chart carries a new, immutable image tag,
   which changes the pod spec and rolls every Deployment.

The build epoch in the version is load-bearing. A bare `0.1.0-<sha>` prerelease
is ordered by *sha string*, not time, so Flux would pin to whichever sha sorted
highest and dev would stop updating; the numeric epoch identifier restores
chronological ordering (see the comment in
`.tektonic/jobs/helm-publish/publish.sh`).

Watch a rollout with:

```bash
flux -n flux-system get helmrelease ocidex-dev
kubectl -n ocidex-dev rollout status deploy/ocidex-dev-api
```

### Tagged releases

Pushing a `v*.*.*` tag runs `helm-release` instead, which resolves each image's
multi-arch index digest with `crane`, bakes them into `image.digests` in
`values.yaml`, and packages the chart at the bare semver with
`appVersion: v<semver>`. A released chart therefore pins every component to an
immutable `...@sha256:...` reference. To track releases rather than `main`, set
the HelmRelease `version` to a semver range such as `">=1.0.0"`.

## Rollback

Flux owns the version, so rolling back means pinning it — not reverting a commit
in this repo:

```bash
flux -n flux-system suspend helmrelease ocidex-dev
# pin chart.spec.version in helmrelease.yaml to the last known-good version,
# commit, then:
flux -n flux-system resume helmrelease ocidex-dev
```

Remove the pin (back to `">=0.0.0-0"`) once a fixed chart is published, or Flux
will hold the release there indefinitely. On a non-Flux cluster,
`helm rollback ocidex-dev <revision> -n ocidex-dev` does the same thing.

Database state is unaffected: Postgres is external to the chart and its PVC
belongs to the CNPG `Cluster`. Note that migrations are **not** rolled back by
either mechanism — a rollback across a schema change needs
`ocidex migrate down` run deliberately.

---

## Troubleshooting

| Symptom | First thing to check |
|---|---|
| Pods stuck `CreateContainerConfigError` | `kubectl -n ocidex-dev describe pod …` — usually `ocidex-secrets` missing or misnamed; verify the homelab Flux app reconciled the Secret and that `existingSecret` matches its name. |
| API pod `CrashLoopBackOff` immediately at startup | `kubectl -n ocidex-dev logs deploy/ocidex-dev-api` — missing required env (`DATABASE_URL`, `NATS_URL`). |
| OAuth login returns 400 `redirect_uri_mismatch` | `api.env.githubRedirectUrl` in the HelmRelease values does not exactly match the OAuth App's "Authorization callback URL". |
| `/api` and `/auth` return the SPA or 404 | Nothing is routing them to the API. With `gatewayApi.enabled=false` the chart renders no HTTPRoute and the web container has no reverse proxy (ADR-038) — check the homelab-owned HTTPRoute exists and lists `/api`+`/auth` *before* the `/` catch-all. |
| Migrate Job fails | `kubectl -n ocidex-dev logs job/ocidex-dev-migrate-<revision>` — usually `DATABASE_URL` shape (it is a keyword DSN, not a URL), CNPG not yet `Ready`, or pgcrypto extension permission. A failing hook blocks the whole `helm upgrade`. |
| HelmRelease stuck / not upgrading | `flux -n flux-system get helmrelease ocidex-dev` and `flux -n flux-system get source chart`. If the version never advances, check that `helm-publish` succeeded in CI and that the chart version sorts above the current one. |
| `https://ocidex.app` returns 404 from Cloudflare | HTTPRoute hostname / `parentRefs` mismatch; `kubectl -n ocidex-dev get httproute -o yaml`. Verify the cloudflare-gateway controller logs accepted the route. |
| API pods `Ready` but `/health` 502 via tunnel | HTTPRoute backendRef name/port wrong — must be `ocidex-dev-web:80` and `ocidex-dev-api:80` (Services expose 80 → containerPort 8080). |
| Postgres unreachable | `kubectl -n ocidex-dev get cluster ocidex-pg` and `kubectl -n ocidex-dev describe cluster ocidex-pg`; CNPG reports primary/replica state and bootstrap errors there. See [`docs/OPERATIONS.md`](OPERATIONS.md). |
| NATS pod won't schedule | `nats.storage.storageClass` must name a class the cluster has (`local-path` on the homelab Talos cluster); set `nats.storage.emptyDir: true` to run without a PVC. |
