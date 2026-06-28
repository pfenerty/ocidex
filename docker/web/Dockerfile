# Build stage
FROM --platform=$BUILDPLATFORM docker.io/node:22-bookworm AS build

WORKDIR /app

COPY web/package.json web/package-lock.json* ./
RUN --mount=type=cache,target=/root/.npm npm install

COPY web/ .
RUN npx tsc && npx vite build

# Serve stage
FROM docker.io/caddy:2-alpine
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"

COPY web/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv

EXPOSE 80
