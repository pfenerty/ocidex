# The mock OIDC issuer for `make demo` (ocidex-vvw6.3). It signs with an ephemeral key, accepts
# any client_id and vouches for whoever the sign-in picker names, so it is never published:
# docker-compose.demo.yml builds it locally, and no CI task builds this file. It lives apart
# from docker/Dockerfile so it cannot be mistaken for, or tested as, a shipped image.
FROM --platform=$BUILDPLATFORM ghcr.io/pfenerty/apko-cicd/golang:1.27@sha256:954807ca8051a8c3f4236691e1e8652e35322980a75fd71430515f9d51000044 AS build
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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /app/mock-idp /mock-idp
ENTRYPOINT ["/mock-idp"]
