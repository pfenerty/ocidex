# API Versioning Policy

OCIDex uses a URL-prefix versioning scheme. All stable endpoints are under `/api/v1/`.

## Current Stable Prefix

```
/api/v1/
```

This prefix is stable. All clients and integrations should use `/api/v1/` as the base path. The interactive docs UI is at `/docs` and the machine-readable spec at `/openapi.json`.

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
