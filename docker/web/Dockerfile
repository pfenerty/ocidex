# Build stage
#
# apko nodejs:24 rather than docker.io/node:24-bookworm: 97 MiB vs 390 MiB compressed. The CI
# chain's buildkitd runs --oci-worker-snapshotter=native, which copies rather than overlays, so
# the base size is paid again on every layer of this stage — and the resident footprint competes
# for the shared 14 GiB GC ceiling with the nine Go image builds (ocidex-5343).
FROM --platform=$BUILDPLATFORM ghcr.io/pfenerty/apko-cicd/nodejs:24@sha256:1df196e67637b1f334a4d93444236704f49d7c25572585dbc4e36863edb8b7bc AS build

# The apko image runs as uid 1001 (base/apko.yaml `run-as: nonroot`) with no HOME in its env, so
# npm would resolve its cache dir somewhere the mount below does not cover — the same trap the Go
# builder-base hit in ocidex-2j2. Root is safe here: this stage is discarded, and the shipped
# nginx stage still runs as uid 65532.
USER root
ENV HOME=/root \
    NPM_CONFIG_CACHE=/root/.npm

WORKDIR /app

COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY web/ .
RUN npm run build

# Serve stage (labels injected via buildctl CLI flags, not Dockerfile)
#
# Static assets only — no reverse proxy. /api and /auth are routed to the API by
# the Gateway HTTPRoute in k8s, and by web/nginx.compose.conf under compose.
# Runs as UID 65532, hence 8080 rather than 80.
FROM cgr.dev/chainguard/nginx@sha256:16d0e55ffe62f55744d9b903d8eb57e533d0f660332a9fbb967d78b4e77c8bdb

COPY web/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /srv
# Third-party license texts for the bundled npm packages, written by rollup-plugin-license
# (web/vite.config.ts) and also served at /third-party-licenses.txt (ocidex-9rqq).
COPY --from=build /app/dist/third-party-licenses.txt /licenses/THIRD_PARTY_NOTICES
COPY LICENSE /licenses/LICENSE

EXPOSE 8080
