# Build stage
FROM --platform=$BUILDPLATFORM docker.io/node:24-bookworm AS build

WORKDIR /app

COPY web/package.json web/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm npm install

COPY web/ .
RUN npx tsc && npx vite build

# Serve stage (labels injected via buildctl CLI flags, not Dockerfile)
#
# Static assets only — no reverse proxy. /api and /auth are routed to the API by
# the Gateway HTTPRoute in k8s, and by web/nginx.compose.conf under compose.
# Runs as UID 65532, hence 8080 rather than 80.
FROM cgr.dev/chainguard/nginx@sha256:171bc52d7bb01604bfb107800e646a02915ec9f98fb145659bb859955d1d7f51

COPY web/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /srv

EXPOSE 8080
