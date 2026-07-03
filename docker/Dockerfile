# Always build on the runner's native platform; cross-compile via GOARCH.
# This avoids QEMU emulation for arm64, which is the main CI slowdown.
FROM --platform=$BUILDPLATFORM ghcr.io/pfenerty/apko-cicd/golang:1.26 AS builder-base

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# ---- Per-binary build stages -------------------------------------------------
# Each stage only compiles one binary; buildkit skips unreferenced stages.

FROM builder-base AS build-api
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/ocidex ./cmd/ocidex

FROM builder-base AS build-scanner-worker
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/scanner-worker ./cmd/scanner-worker

FROM builder-base AS build-enrichment-worker
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/enrichment-worker ./cmd/enrichment-worker

FROM builder-base AS build-oci-metadata-worker
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/oci-metadata-worker ./cmd/oci-metadata-worker

FROM builder-base AS build-user-enricher-worker
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/user-enricher-worker ./cmd/user-enricher-worker

FROM builder-base AS build-provenance-worker
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/provenance-worker ./cmd/provenance-worker

FROM builder-base AS build-vuln-worker
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/vuln-worker ./cmd/vuln-worker

FROM builder-base AS build-operator
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/operator ./cmd/operator

# ---- Final stages (labels injected via buildctl CLI flags, not Dockerfile) ---

FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=build-api /app/bin/ocidex /ocidex
EXPOSE 8080
ENTRYPOINT ["/ocidex"]

FROM gcr.io/distroless/static-debian12:nonroot AS scanner-worker
COPY --from=build-scanner-worker /app/bin/scanner-worker /scanner-worker
ENTRYPOINT ["/scanner-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS enrichment-worker
COPY --from=build-enrichment-worker /app/bin/enrichment-worker /enrichment-worker
ENTRYPOINT ["/enrichment-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS oci-metadata-worker
COPY --from=build-oci-metadata-worker /app/bin/oci-metadata-worker /oci-metadata-worker
ENTRYPOINT ["/oci-metadata-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS user-enricher-worker
COPY --from=build-user-enricher-worker /app/bin/user-enricher-worker /user-enricher-worker
ENTRYPOINT ["/user-enricher-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS provenance-worker
COPY --from=build-provenance-worker /app/bin/provenance-worker /provenance-worker
ENTRYPOINT ["/provenance-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS vuln-worker
COPY --from=build-vuln-worker /app/bin/vuln-worker /vuln-worker
ENTRYPOINT ["/vuln-worker"]

FROM gcr.io/distroless/static-debian12:nonroot AS operator
COPY --from=build-operator /app/bin/operator /operator
ENTRYPOINT ["/operator"]
