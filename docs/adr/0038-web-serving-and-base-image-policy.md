---
status: "accepted"
date: 2026-08-01
decision-makers: Patrick Fenerty
---

# Web serving and base image policy

## Context and Problem Statement

`docker/web/Dockerfile` served the SolidJS bundle from `docker.io/caddy:2-alpine`. Measured with
syft, that image carries **178 packages**: 32 Alpine apks (`curl`, `libcurl`, `openssl` ×2,
`busybox`, `apk-tools`, `zstd`, `brotli`, …) plus 146 Go modules pulled in by Caddy itself — its
ACME client, DNS provider plugins, quic-go. OCIDex exercises almost none of it. The deployment
always sits behind a load balancer or Cloudflare Tunnel, so Caddy was doing two jobs: serving
static files, and reverse-proxying four path prefixes (`/api`, `/auth`, `/health`, `/ready`) to
the API. Every one of those 178 packages is CVE surface we carry to do those two things.

Two adjacent gaps sat in the same layer. The nine Go service images used
`gcr.io/distroless/static-debian12:nonroot` when `static-debian13` was already published. And no
image reference anywhere in the repo was digest-pinned, so `FROM node:24-bookworm` and friends
were mutable — builds were not reproducible and a base-image change could land silently.

Investigating a replacement web server surfaced a better answer for the proxying half of the job.
The four path prefixes are pure L7 routing. In Kubernetes there is already an L7 router in the
request path — the Gateway — and the routing belongs there, not in a second server behind it.

## Decision Drivers

* Minimise CVE surface in the runtime images; that was the motivating complaint.
* The web tier only ever needs to serve static files and fall back to `index.html`.
* Reproducible builds — a given commit should produce a bit-identical image.
* Keep the same-origin `/api` the SPA depends on (`web/src/api/client.ts`, and the GitHub OAuth
  redirect, which is derived from `r.Host`).
* Don't take on maintenance the tooling can do: Renovate should own digest churn.

## Considered Options

* Keep Caddy, accept the package count.
* `nginx:alpine` — familiar, but still Alpine with a full apk surface.
* `cgr.dev/chainguard/nginx` with the reverse proxy retained in nginx.
* `cgr.dev/chainguard/nginx` with routing moved to the Gateway HTTPRoute.

## Decision Outcome

Chosen option: **`cgr.dev/chainguard/nginx`, with L7 routing moved into the Gateway HTTPRoute**.

The image is **19 packages**, all Wolfi (`nginx-mainline`), verified on the built OCIDex image and
not just the base — a 9× reduction from 178. Moving the four path prefixes to
`charts/ocidex/templates/httproutes.yaml` leaves `web/nginx.conf` with **zero upstreams**, which
matters more than it first appears: nginx resolves literal `proxy_pass` hostnames at
*config-load* time and refuses to start if they don't resolve, where Caddy resolves lazily. A web
pod that cannot start because the API is down is a worse failure mode than the one we had. With
no upstreams, that class of failure is gone by construction.

Alongside it, three supporting decisions:

* The nine Go service final stages move to `gcr.io/distroless/static-debian13:nonroot`
  (5 packages: `base-files`, `media-types`, `netbase`, `tzdata`, `tzdata-legacy`). The binaries
  are `CGO_ENABLED=0` static, so there is no libc coupling to break.
* The NATS image moves from a hardcoded string in `statefulset-nats.yaml` into
  `charts/ocidex/values.yaml` under `nats.image.{repository,tag}`, where Renovate's `helm-values`
  manager can see it. It also lets operators point at an external NATS.
* `renovate.json` sets `pinDigests: true` scoped to `matchManagers: ["dockerfile",
  "docker-compose", "helm-values"]`, and the existing automerge rule is extended to cover
  `digest` updates.

### Consequences

* Good, because the web runtime drops from 178 packages to 19, and the Go runtimes to 5.
* Good, because the web pod no longer has a startup-time dependency on the API resolving.
* Good, because routing is declared once, in the resource whose job is routing, and is visible in
  `kubectl get httproute` rather than buried in a container's config file.
* Good, because every runtime and build image is digest-pinned, so builds are reproducible and
  Renovate owns the rebase.
* Bad, because the image has **no shell**. There is no `RUN`, no entrypoint script, no envsubst —
  so the old `BACKEND_URL` substitution is impossible, and the shipped
  `conf.d/nginx.default.conf` (a complete `server{}` block) cannot be deleted at build time. We
  replace `/etc/nginx/nginx.conf` wholesale instead and deliberately do not include `conf.d/`.
* Bad, because the image runs as UID 65532 and so cannot bind a privileged port. The container
  port is 8080; the web Service keeps `port: 80` with `targetPort: 8080`, so the HTTPRoute
  backendRef is unaffected.
* Bad, because installs with `gatewayApi.enabled=false` — the chart default — now have no
  same-origin `/api`. This is called out in `values.yaml` next to the `gatewayApi` block and in a
  `NOTES.txt` warning branch, with three remedies: enable `gatewayApi`, supply equivalent Ingress
  rules, or build the frontend with `VITE_API_URL` set and list the frontend origin in
  `api.env.corsAllowedOrigins`. Making the third option actually work required two frontend
  fixes: `web/src/api/queries/registries.ts` had a bare `fetch('/api/v1/...')` bypassing
  `API_BASE_URL`, and `client.ts` needed `credentials: "include"` for the cross-origin session
  cookie.
* Bad, because docker-compose has no L7 router and therefore cannot inherit the Gateway's
  routing. It bind-mounts `web/nginx.compose.conf` at `/etc/nginx/ocidex.d/proxy.conf`, included
  from inside the `server{}` block in `nginx.conf`. The image ships nothing in that directory; a
  wildcard `include` matching zero files is not an error in nginx, so the same image serves both
  deployments. This is a second place where the four paths are enumerated — accepted because the
  alternative is either a compose-specific image or dragging the upstream back into the k8s
  config.

### Confirmation

Verified before commit, per the standing rule that CI is not the test loop:

* `syft ocidex-web:test -o json | jq '.artifacts | length'` → **19** on the built image.
* `nginx -t` run as UID 65532 against the real image, both with and without the compose snippet
  mounted → "syntax is ok" in both cases (confirming the zero-match wildcard include is legal).
* Live container: `/` → 200, `/some/spa/route` → 200 (SPA fallback), `Content-Encoding: gzip`,
  logs on stdout/stderr with no pid or log permission errors.
* Compose path with the snippet mounted against a stub upstream: all four prefixes proxy, `Host`
  is preserved end-to-end, and `/` and `/healthy` correctly fall through to the SPA rather than
  being captured by the `Exact` matches.
* `helm lint` clean; `helm template` shows the HTTPRoute rule order, `targetPort: 8080`,
  `containerPort: 8080`, both probes on 8080, and the templated NATS image.

**Gateway rule ordering — confirmed.** The `GatewayClass cloudflare` controller
([pl4nty/cloudflare-kubernetes-gateway](https://github.com/pl4nty/cloudflare-kubernetes-gateway))
translates HTTPRoutes into Cloudflare Tunnel ingress rules, which are **first-match-in-order**, so
the whole design rests on `/api` being emitted ahead of the `/` catch-all. Verified two ways:

* Empirically against the live cluster. `https://ocidex.app/api/v1/<random>` returned a
  `text/plain` 404 from the API — not the SPA's `text/html` fallback — and the marker appeared in
  the **api** pod's logs and never in the **web** pod's. Rule 1 wins over the catch-all, and the
  request does not transit the web pod.
* In the controller source. `internal/controller/httproute_controller.go` builds its ingress list
  with `for _, rule := range route.Spec.Rules`, appending in slice order, so ordering is preserved
  by construction rather than by luck.

The nginx-`proxy_pass` fallback is therefore not needed.

Two caveats found while reading that code, neither blocking:

* **`match.Path.Type` is ignored** — the controller reads only `*match.Path.Value`, so our
  `Exact: /health` is emitted as Cloudflare ingress `Path: "/health"`, which Cloudflare treats as
  a regex and would also match `/healthy`. We keep `Exact` regardless: it is the correct spec
  semantic, conformant controllers (Cilium et al.) honour it, and on Cloudflare it degrades to
  the prefix behaviour we would otherwise have written by hand.
* **Match order *within* a rule is nondeterministic** — matches are collected into a
  `map[string]bool` and emitted with `for path := range paths`. This is harmless for our route
  because all four matches in rule 1 share one backendRef, but a future rule that mixes matches of
  differing specificity pointing at *different* backends would be a coin flip. Keep one backend
  per rule.

## Pros and Cons of the Options

### Keep Caddy

* Good, because zero work, and lazy upstream resolution means it starts when the API is down.
* Bad, because 178 packages for static file serving plus four proxy rules.
* Bad, because the bulk of the surface is Caddy's own feature set (ACME, DNS plugins, QUIC) that
  a load-balanced deployment never touches.

### `nginx:alpine`

* Good, because it is the most familiar option and needs no design change.
* Bad, because it is still a full Alpine userland — the apk surface is most of what we are trying
  to shed, and the package count lands far closer to 178 than to 19.

### Chainguard nginx, proxy retained in nginx

* Good, because it is a drop-in shape change: same responsibilities, smaller image.
* Bad, because a literal `proxy_pass` hostname is resolved at config load, so the web pod fails to
  start whenever the API Service is unresolvable.
* Bad, because it keeps L7 routing in two places (Gateway and nginx) with no benefit.
* Bad, because it forces the api Service onto 8080 to match.

### Chainguard nginx, routing at the Gateway

* Good, because nginx ends up with one job and no upstreams.
* Good, because routing lives in the routing resource.
* Bad, because non-Gateway installs need explicit configuration (documented; see Consequences).
* Bad, because compose needs its own snippet.

## More Information

Scope note on digest pinning: the `.tekton/` and `.tektonic/` CI images are **deliberately
excluded**. `ghcr.io/pfenerty/apko-cicd/base:stable` appears over 100 times and is an
intentionally moving tag; pinning it would force a Renovate PR plus a `make tekton-synth` on
every upstream base rebuild, for images that never reach production. The
`.tektonic/**/*.ts` customManager in `renovate.json` is left untouched for the same reason.

`cgr.dev/chainguard/nginx` gets `minimumReleaseAge: "0"`, overriding the global 3-day hold.
Chainguard publishes only `:latest` on the free tier, so the digest *is* the version — and a new
digest is usually the CVE fix we chose the image for. Holding it for three days would delay
exactly the updates that motivated the decision.

Supersedes nothing. Related: ADR-031 (deployment architecture).
