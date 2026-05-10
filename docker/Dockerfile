# ---- Builder ----------------------------------------------------------------
FROM docker.io/golang:1.25-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -o /app/bin/ocidex ./cmd/ocidex && \
    CGO_ENABLED=0 GOOS=linux go build -o /app/bin/scanner-worker ./cmd/scanner-worker && \
    CGO_ENABLED=0 GOOS=linux go build -o /app/bin/enrichment-worker ./cmd/enrichment-worker

# ---- api --------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=builder /app/bin/ocidex /ocidex
EXPOSE 8080
ENTRYPOINT ["/ocidex"]

# ---- scanner-worker ---------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS scanner-worker
COPY --from=builder /app/bin/scanner-worker /scanner-worker
ENTRYPOINT ["/scanner-worker"]

# ---- enrichment-worker ------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS enrichment-worker
COPY --from=builder /app/bin/enrichment-worker /enrichment-worker
ENTRYPOINT ["/enrichment-worker"]
