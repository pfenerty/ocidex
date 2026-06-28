# ---- Builder ----------------------------------------------------------------
# Always build on the runner's native platform; cross-compile via GOARCH.
# This avoids QEMU emulation for arm64, which is the main CI slowdown.
FROM --platform=$BUILDPLATFORM docker.io/golang:1.26-bookworm AS builder

ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    LDFLAGS="-s -w \
      -X github.com/pfenerty/ocidex/internal/version.Version=${VERSION} \
      -X github.com/pfenerty/ocidex/internal/version.Commit=${COMMIT} \
      -X github.com/pfenerty/ocidex/internal/version.Date=${DATE}" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/ocidex ./cmd/ocidex && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/scanner-worker ./cmd/scanner-worker && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/enrichment-worker ./cmd/enrichment-worker && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/oci-metadata-worker ./cmd/oci-metadata-worker && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/user-enricher-worker ./cmd/user-enricher-worker && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/provenance-worker ./cmd/provenance-worker && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/operator ./cmd/operator

# ---- api --------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS api
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"
COPY --from=builder /app/bin/ocidex /ocidex
EXPOSE 8080
ENTRYPOINT ["/ocidex"]

# ---- scanner-worker ---------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS scanner-worker
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"
COPY --from=builder /app/bin/scanner-worker /scanner-worker
ENTRYPOINT ["/scanner-worker"]

# ---- enrichment-worker ------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS enrichment-worker
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"
COPY --from=builder /app/bin/enrichment-worker /enrichment-worker
ENTRYPOINT ["/enrichment-worker"]

# ---- oci-metadata-worker ----------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS oci-metadata-worker
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"
COPY --from=builder /app/bin/oci-metadata-worker /oci-metadata-worker
ENTRYPOINT ["/oci-metadata-worker"]

# ---- user-enricher-worker ---------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS user-enricher-worker
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"
COPY --from=builder /app/bin/user-enricher-worker /user-enricher-worker
ENTRYPOINT ["/user-enricher-worker"]

# ---- provenance-worker ------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS provenance-worker
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"
COPY --from=builder /app/bin/provenance-worker /provenance-worker
ENTRYPOINT ["/provenance-worker"]

# ---- operator ---------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS operator
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.source="https://github.com/pfenerty/ocidex"
COPY --from=builder /app/bin/operator /operator
ENTRYPOINT ["/operator"]
