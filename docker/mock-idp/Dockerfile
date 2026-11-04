# The mock OIDC issuer for `make demo` (ocidex-vvw6.3). It signs with an ephemeral key, accepts
# any client_id and vouches for whoever the sign-in picker names, so it is never published:
# docker-compose.demo.yml builds it locally, and no CI task builds this file. It lives apart
# from docker/Dockerfile so it cannot be mistaken for, or tested as, a shipped image.
FROM --platform=$BUILDPLATFORM ghcr.io/pfenerty/apko-cicd/golang:1.27@sha256:17333d9b39ead4ccbca2357ff673b47f863c1ca5f80be10c56abe249c02f8be6 AS build
USER root
ENV GOPATH=/go \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /app/mock-idp ./cmd/mock-idp

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /app/mock-idp /mock-idp
ENTRYPOINT ["/mock-idp"]
