# API Versioning Policy

OCIDex uses a URL-prefix versioning scheme. All stable endpoints are under `/api/v1/`.

## Current Stable Prefix

```
/api/v1/
```

This prefix is stable. All clients and integrations should use `/api/v1/` as the base path. The interactive docs UI is at `/docs` and the machine-readable spec at `/openapi.json`.

## Contract Version and Build Version

The OpenAPI `info.version` is the **contract version** of `/api/v1`
(`api.ContractVersion` in `internal/api/health.go`, per
[ADR-052](adr/0052-v1-compatibility.md)). It is changed on purpose: the minor goes up on an
additive change, and the major goes up only together with a new `/api/vN` prefix. It is
never the server's build version, so the generated spec is the same for every build.

The version of the running server is reported by `GET /api/v1/`:

```json
{ "version": "v1", "build": "v1.2.3" }
```

`build` is the release tag for release images. Otherwise it is the Go module version, or
`dev` for a local build. It is the same version that `ocidex --version` prints.

## Go SDK

`pkg/client` is a separate Go module, `github.com/pfenerty/ocidex/pkg/client`, so importing it
does not bring in the server's dependency graph. It is released with
`make release VERSION=pkg/client/vX.Y.Z`, independently of server releases, and its exported
identifiers follow semver (ADR-052). Its major version tracks the API's `/api/vN` prefix.

In this repository, `go.work` joins the SDK to the root module, so a change to both builds and
tests together. The root `go.mod` still requires a **published** SDK version, because
`go install github.com/pfenerty/ocidex/cmd/...@<version>` ignores `go.work`. When the binaries
start using new SDK API, release the SDK first and update the requirement
(`GOWORK=off go get github.com/pfenerty/ocidex/pkg/client@vX.Y.Z`). A server release refuses to
tag while the root module does not build without `go.work`.

## What Counts as a Breaking Change

A breaking change is any modification that would cause a correctly-written client targeting the current spec to fail or behave incorrectly:

- Removing an endpoint
- Removing or renaming a required request field
- Removing or renaming a response field that clients are expected to consume
- Changing an HTTP method on an existing operation
- Changing the meaning of an existing status code
- Narrowing a field's accepted value set (e.g., changing a `string` to an enum)

The following are **not** breaking changes:

- Adding a new endpoint
- Adding a new optional request field (with a reasonable default)
- Adding a new response field
- Adding a new query parameter (optional, with a default)
- Expanding an accepted value set

## Breaking-Change Check in CI

Every PR that touches Go runs the `openapi-breaking` check. It runs `oasdiff breaking`
(pinned image, `.tektonic/jobs/openapi-breaking/`) on the committed `web/openapi.json`
against the spec at the latest release tag, and fails on any error-level change, such as:

- a removed endpoint, response field or required property;
- a new required request field;
- a new enum value in a response.

Additive changes pass.

To reproduce it locally:

```bash
git fetch --tags
TAG=$(git -c versionsort.suffix=- tag -l 'v[0-9]*' --sort=-v:refname | head -n1)
git show "$TAG:web/openapi.json" > /tmp/base.json
oasdiff breaking /tmp/base.json web/openapi.json --fail-on ERR \
  --err-ignore web/openapi-breaking-accepted.txt
```

**Accepting a break on purpose.** Add a line to `web/openapi-breaking-accepted.txt` in the
same PR. The line holds the operation and the change text that oasdiff prints, and the file's
header explains how to produce it. The entry is part of the diff, so a reviewer has to approve
the break explicitly. A label or a commit flag would be easier to miss. Before 1.0, an
accepted break means bumping the minor version. From 1.0 on, an accepted break on `/api/v1`
means the process below. The file is cleared after each release, because that release's spec
becomes the new base.

## How Breaking Changes Are Handled

1. A new major prefix (`/api/v2/`) is introduced alongside `/api/v1/`.
2. Both versions are served simultaneously for a deprecation window (minimum one release cycle).
3. The deprecated prefix returns an `X-Deprecated` response header with a sunset date.
4. Removal of the old prefix happens no sooner than the announced sunset date.

No `/api/v2/` exists yet. If you are building tooling that needs to survive a v1→v2 transition, check the `Deprecated` field in the OpenAPI operation objects — operations marked deprecated will be removed in the next major version.

## Spec Generation

The OpenAPI spec is generated from Go types at build time:

```bash
flox activate -- make openapi
```

This regenerates `web/openapi.json` and `web/src/types/openapi.d.ts`. CI enforces that the committed spec matches the code (`make openapi-check`). Any endpoint addition, removal, or type change that is not reflected in the committed spec will fail CI.
