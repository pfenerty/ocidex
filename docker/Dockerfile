# Always build on the runner's native platform; cross-compile via GOARCH.
# This avoids QEMU emulation for arm64, which is the main CI slowdown.
FROM --platform=$BUILDPLATFORM ghcr.io/pfenerty/apko-cicd/golang:1.27@sha256:825edfa509d15ae141c90513de65c2e275250391682a2a7a0db2fec27ab12bb2 AS builder-base

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
# Do not switch to ./cmd/... — that would also build specgen, authmatrix and the other dev tools,
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
# Third-party notices for the binaries above, shipped as /licenses/THIRD_PARTY_NOTICES in
# every image (ocidex-9rqq): ~3MB, ~100KB compressed. `go-licenses report` (pinned in
# tools/go.mod, the classifier `make license-check` uses) renders every linked package's
# license text through docker/licenses/notices.tpl, with the build's GOOS/GOARCH so it sees
# the graph that is actually linked. It also looks up license URLs over the network; a failed
# lookup only warns, and the template doesn't use them.
#
# pkg/client is our own SDK module (covered by LICENSE). The modules in
# docker/go-licenses-unclassified.txt carry licenses go-licenses can't classify: they are
# ignored there and their license files appended by hand (go list -m fails on an entry that
# is no longer a dependency). Any other package with no license file go-licenses can find
# fails the template, so a new dependency can't ship without its notice. The Go standard library's notices and the full Apache-2.0 text
# (which those short-notice modules refer to) come from docker/licenses/.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build <<'NOTICES'
set -eu
GOWORK=off go build -modfile=tools/go.mod -o /usr/local/bin/go-licenses github.com/google/go-licenses/v2
export CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}
unclassified=$(grep -v -e '^#' -e '^$' docker/go-licenses-unclassified.txt)
ignore="--ignore github.com/pfenerty/ocidex/pkg/client"
for mod in $unclassified; do ignore="$ignore --ignore $mod"; done
section() { printf '\n%s\n%s\n\n' "================================================================================" "$1"; }

mkdir -p /app/licenses
cp LICENSE /app/licenses/LICENSE
{
  cat docker/licenses/preamble
  section "Go standard library and runtime (BSD-3-Clause)"
  cat docker/licenses/go/LICENSE docker/licenses/go/PATENTS
  go-licenses report --template docker/licenses/notices.tpl $ignore \
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
  for mod in $unclassified; do
    section "$(go list -m -f '{{.Path}} {{.Version}}' "$mod")"
    cat "$(go list -m -f '{{.Dir}}' "$mod")"/LICENSE*
  done
  section "Apache License 2.0 (full text)"
  cat docker/licenses/Apache-2.0.txt
} > /app/licenses/THIRD_PARTY_NOTICES
NOTICES
# Deliberately absent: ./cmd/mock-idp, ./cmd/specgen, ./cmd/authmatrix. The
# first is a mock OIDC issuer that hands a session to whoever asks; the others
# are build-time generators. None belongs in a shipped image, and
# TestMockIDPShipsInNoImage keeps the first of those honest.

# ---- Final stages (labels injected via buildctl CLI flags, not Dockerfile) ---

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS api
COPY --from=build-all /app/bin/ocidex /ocidex
COPY --from=build-all /app/licenses /licenses
EXPOSE 8080
ENTRYPOINT ["/ocidex"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS scanner-worker
COPY --from=build-all /app/bin/scanner-worker /scanner-worker
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/scanner-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS oci-metadata-worker
COPY --from=build-all /app/bin/oci-metadata-worker /oci-metadata-worker
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/oci-metadata-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS git-worker
COPY --from=build-all /app/bin/git-worker /git-worker
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/git-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS user-enricher-worker
COPY --from=build-all /app/bin/user-enricher-worker /user-enricher-worker
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/user-enricher-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS provenance-worker
COPY --from=build-all /app/bin/provenance-worker /provenance-worker
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/provenance-worker"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS vuln-worker
COPY --from=build-all /app/bin/vuln-worker /vuln-worker
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/vuln-worker"]

# The inventory agent runs in the cluster it reports on, which is not necessarily a cluster
# OCIDex is deployed in (ADR-044 K1) — so it ships as its own image and its own chart
# (charts/ocidex-k8s-agent) rather than as another Deployment in charts/ocidex.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS k8s-agent
COPY --from=build-all /app/bin/k8s-agent /k8s-agent
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/k8s-agent"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS operator
COPY --from=build-all /app/bin/operator /operator
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/operator"]

# The CLI ships as an image so a Tekton task or a K8s Job can run it without a Go toolchain
# (ADR-029, Distribution). distroless static carries ca-certificates for HTTPS and sets
# HOME=/home/nonroot, which is all `ocidex-cli` needs to resolve its config path.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99 AS cli
COPY --from=build-all /app/bin/ocidex-cli /ocidex-cli
COPY --from=build-all /app/licenses /licenses
ENTRYPOINT ["/ocidex-cli"]
