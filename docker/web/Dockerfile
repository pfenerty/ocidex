# Build stage
FROM --platform=$BUILDPLATFORM docker.io/node:24-bookworm AS build

WORKDIR /app

COPY web/package.json web/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm npm install

COPY web/ .
RUN npx tsc && npx vite build

# Serve stage (labels injected via buildctl CLI flags, not Dockerfile)
FROM docker.io/caddy:2-alpine

COPY web/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv

EXPOSE 80
