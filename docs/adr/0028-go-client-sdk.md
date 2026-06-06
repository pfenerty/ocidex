# ADR-028: Go Client SDK Design

**Status:** Accepted  
**Date:** 2026-06-06  
**Epic:** ocidex-3nu — 1.5 Go Client SDK

---

## Context

The CLI (ocidex-e3g), K8s operator (ocidex-01v), and Terraform provider (ocidex-dsy) all need a typed Go client for the OCIDex HTTP API. Three options were evaluated for generating the types:

1. **oapi-codegen v2** — types-only generation from the OpenAPI spec
2. **ogen** — full client/server generator with strong 3.1 support
3. **Hand-written types** — mirror `internal/api/types.go` manually

## Decision

Use **oapi-codegen v2 in types-only mode** (`generate: {models: true}`), with a pre-processing step to downconvert the 3.1 spec to 3.0.

Huma v2 emits OpenAPI 3.1 (nullable arrays as `type: [array, null]`). oapi-codegen does not yet support 3.1. `scripts/spec-to-3.0.py` converts the 50 nullable-array occurrences to the 3.0 equivalent (`type: array + nullable: true`) before codegen runs.

**ogen** was rejected: it generates HTTP client boilerplate in addition to types, coupling generated and hand-written code. The goal is generated *data types* only; the `Client` interface and HTTP implementation are hand-written (ocidex-3nu.3/4/5/6) for ergonomics and testability.

**Hand-written types** were rejected: they drift silently from the spec and require manual updates after every API change. Generated types make drift a CI failure.

## Client Interface

The `Client` interface (`pkg/client/client.go`, implemented in ocidex-3nu.3) is hand-written for ergonomics. Consumers and tests program to this interface; `httpClient` is the production implementation. A `FakeClient` (ocidex-3nu.7) implements `Client` for use in CLI/operator/provider tests.

## Error Hierarchy

Typed sentinels allow callers to `errors.Is`:

- `ErrNotFound` — HTTP 404
- `ErrForbidden` — HTTP 403
- `ErrConflict` — HTTP 409
- `APIError{Status, Detail}` — all other 4xx/5xx responses

## Pagination

`Page[T]` is a generic type (`page.go`) mirroring the API's paginated list responses. Pagination helpers live in the same file.

## File Layout

```
pkg/client/
  .oapi-codegen.yml     # codegen config — types-only, output: pkg/client/types.go
  doc.go                # package-level godoc
  types.go              # GENERATED — DO NOT EDIT; regenerate with make generate-client
  client.go             # hand-written Client interface (ocidex-3nu.3)
  errors.go             # ErrNotFound, ErrForbidden, ErrConflict, APIError (ocidex-3nu.3)
  page.go               # Page[T] generic + pagination helpers (ocidex-3nu.3)
  http_client.go        # httpClient struct + New constructor (ocidex-3nu.3)
  registry.go           # Registry + auth method implementations (ocidex-3nu.4)
  sbom.go               # SBOM + artifact method implementations (ocidex-3nu.5)
  component.go          # Component + job + stats implementations (ocidex-3nu.6)
  fake_client.go        # FakeClient for testing consumers (ocidex-3nu.7)
  *_test.go             # httptest-based unit tests (ocidex-3nu.7)
```

## Update Strategy

`make generate-client` must be run after any change to the API surface (`internal/api/types.go`, `internal/api/router.go`). The chain is:

```
internal/api/types.go → make openapi → web/openapi.json → make generate-client → pkg/client/types.go
```

`make generate-client-check` verifies the committed file matches the spec; it runs in CI as part of `make check`.

`scripts/spec-to-3.0.py` is a narrow conversion script — it handles only the nullable-array pattern that Huma v2 currently emits. If the spec gains other 3.1-only constructs, the script must be extended, or the project should migrate to a tool with native 3.1 support.
