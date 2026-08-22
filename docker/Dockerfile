# Always build on the runner's native platform; cross-compile via GOARCH.
# This avoids QEMU emulation for arm64, which is the main CI slowdown.
FROM --platform=$BUILDPLATFORM ghcr.io/pfenerty/apko-cicd/golang:1.26 AS builder-base

# The apko builder image runs as uid 1001 (base/apko.yaml `run-as: nonroot`) with no
# GOPATH/GOCACHE/GOMODCACHE in its env, so Go resolved them under $HOME=/home/nonroot and the
# cache mounts below were writing to paths Go never read (ocidex-2j2). Root is safe here: this
# stage is discarded, and the shipped distroless stages still run as nonroot.
USER root
ENV GOPATH=/go \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# ---- Shared build stage ------------------------------------------------------
# One compile for all ten shipped binaries. The dependency graph (cosign/sigstore-go and its
# ~786 transitive deps, per ADR-037) dominates compile time, so compiling it once and linking
# ten mains replaces ten cold compiles of the same graph. The serial image chain shares one
# buildkit root, so only the first image build runs this stage; the rest hit it CACHED.
#
# Do not switch to ./cmd/... — that would also build specgen, dbcheck and the backfill tools,
# none of which ship as images.
FROM builder-base AS build-all
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
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags "${LDFLAGS}" -o /app/bin/ \
      ./cmd/ocidex \
      ./cmd/scanner-worker \
      ./cmd/oci-metadata-worker \
      ./cmd/git-worker \
      ./cmd/user-enricher-worker \
      ./cmd/provenance-worker \
      ./cmd/vuln-worker \
      ./cmd/k8s-agent \
      ./cmd/operator \
      ./cmd/ocidex-cli

# ---- Final stages (labels injected via buildctl CLI flags, not Dockerfile) ---

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS api
COPY --from=build-all /app/bin/ocidex /ocidex
EXPOSE 8080
ENTRYPOINT ["/ocidex"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS scanner-worker
COPY --from=build-all /app/bin/scanner-worker /scanner-worker
ENTRYPOINT ["/scanner-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS oci-metadata-worker
COPY --from=build-all /app/bin/oci-metadata-worker /oci-metadata-worker
ENTRYPOINT ["/oci-metadata-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS git-worker
COPY --from=build-all /app/bin/git-worker /git-worker
ENTRYPOINT ["/git-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS user-enricher-worker
COPY --from=build-all /app/bin/user-enricher-worker /user-enricher-worker
ENTRYPOINT ["/user-enricher-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS provenance-worker
COPY --from=build-all /app/bin/provenance-worker /provenance-worker
ENTRYPOINT ["/provenance-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS vuln-worker
COPY --from=build-all /app/bin/vuln-worker /vuln-worker
ENTRYPOINT ["/vuln-worker"]

# The inventory agent runs in the cluster it reports on, which is not necessarily a cluster
# OCIDex is deployed in (ADR-044 K1) — so it ships as its own image and its own chart
# (charts/ocidex-k8s-agent) rather than as another Deployment in charts/ocidex.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS k8s-agent
COPY --from=build-all /app/bin/k8s-agent /k8s-agent
ENTRYPOINT ["/k8s-agent"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS operator
COPY --from=build-all /app/bin/operator /operator
ENTRYPOINT ["/operator"]

# The CLI ships as an image so a Tekton task or a K8s Job can run it without a Go toolchain
# (ADR-029, Distribution). distroless static carries ca-certificates for HTTPS and sets
# HOME=/home/nonroot, which is all `ocidex-cli` needs to resolve its config path.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7 AS cli
COPY --from=build-all /app/bin/ocidex-cli /ocidex-cli
ENTRYPOINT ["/ocidex-cli"]
