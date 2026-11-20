---
title: The REST API
description: Authenticate, page through results and handle errors with the OCIDex REST API.
sidebar:
  order: 1
---

All endpoints are under `/api/v1`, on the same host as the UI. Every operation is in the
[API reference](/reference/api/), generated from the server's OpenAPI description. Each running
server also serves its own:

- an interactive reference at `/api/docs`;
- the OpenAPI 3.1 document at `/api/openapi.json` (and `/api/openapi.yaml`).

Every release attaches the same document to its GitHub release, as `openapi.json` and
`openapi.yaml`.

## Authentication

Send an API key as a bearer token:

```sh
curl -fsS https://ocidex.example.com/api/v1/users/me \
  -H "Authorization: Bearer $OCIDEX_API_KEY"
```

Keys look like `ocidex_…`. A key acts for the user who created it, limited to the capabilities it
was given, and is never stronger than that user's roles. Requests without a key are anonymous:
they see public namespaces only, and get a narrower answer rather than an error.

An admin's key reaches the admin-only routes (user roles, job retries, system status) only if it
carries the `installation_admin` capability. Keys created before that capability existed don't
have it; create a new key if you need one for those routes. A key can only create or delete
keys within its own capabilities.

A key can be given an expiry when it is created (`expiresAt`, or `ocidex-cli key create --expires-in
720h`); after it, the key is refused like an unknown one. Keys without one work until revoked.

The UI uses a session cookie instead. A write authenticated by cookie must come from an allowed
origin, so scripts should always use a key.

## Names and shapes

- **Field names are camelCase** everywhere: in bodies, query parameters and sort keys
  (`subjectVersion`, `sort=cvssScore`).
- **Errors** are [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem documents:
  `{ "title", "status", "detail", "errors": [...] }`, with `Content-Type: application/problem+json`.
- **IDs** are UUIDs.

## Paging

Lists use one of two envelopes:

| Kind | Request | Response |
| --- | --- | --- |
| Numbered pages, for computed lists | `?limit=&offset=` | `pagination: { total, limit, offset }` |
| Cursors, for append-only lists | `?limit=&cursor=` | `pagination: { limit, hasMore, nextCursor }` |

Pass a cursor back exactly as you got it; it's opaque.

## Rate limits

SBOM ingest and a few expensive reads are rate-limited per user, 120 requests a minute each by
default. Over the limit, the API answers `429` with a `Retry-After` header. Back off and retry.
An operator can raise the limits for a busy installation.

## Uploading an SBOM

`POST /api/v1/sboms` takes a CycloneDX JSON document as the body. Query parameters name where it
came from and what it describes:

| Parameter | |
| --- | --- |
| `source` | **Required.** The upload source, as a UUID or `<namespace>/<name>`. The SBOM lands in that source's namespace. |
| `version` | The version or tag the SBOM describes. |
| `architecture` | `amd64`, `arm64` and so on. |
| `buildDate` | When the artifact was built, RFC 3339. |
| `subjectType`, `subjectName`, `subjectGroup`, `subjectPurl` | What the SBOM describes, for anything that isn't a container image. |
| `digest` | The sha256 of the artifact itself (not of the SBOM). Required for anything that isn't a container image. |

A **container image's** SBOM must end up with a version, an architecture and a build date. OCIDex
reads them from the image's labels when the SBOM carries them (syft records them), and the
parameters override what it finds.

```sh
syft registry:ghcr.io/acme/api@sha256:… -o cyclonedx-json > sbom.json
curl -fsS -X POST "https://ocidex.example.com/api/v1/sboms?source=acme/ci&version=1.4.2&architecture=amd64&buildDate=2026-11-14T10:00:00Z" \
  -H "Authorization: Bearer $OCIDEX_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @sbom.json
```

Uploading the same image digest twice stores it once.

## Versions and compatibility

`/api/v1` is stable. Within it, OCIDex only makes changes that a correctly written client keeps
working through:

- **Not breaking:** a new endpoint, a new optional request field or query parameter, a new
  response field, a wider set of accepted values.
- **Breaking:** removing an endpoint or a field you consume, renaming a required field, changing
  a method or a status code's meaning, narrowing what a field accepts.

A breaking change means a new prefix, `/api/v2`, served alongside `/api/v1` for at least one
release, with the old prefix marking its responses deprecated before it's removed. Operations that
will go in the next major version are marked `deprecated` in the OpenAPI document. No `/api/v2`
exists yet. Every pull request is checked against the last release's spec, so an accidental break
can't ship.

Two version numbers are worth telling apart:

- The OpenAPI document's `info.version` is the **contract version** of `/api/v1`. It changes only
  when the contract does.
- `GET /api/v1/` reports the **running server's** build:

  ```json
  { "version": "v1", "build": "v1.2.3", "commit": "bf2bab70…", "builtAt": "…", "vulnDbBuiltAt": "…" }
  ```

## Go SDK

`github.com/pfenerty/ocidex/pkg/client` is a typed Go client for the API. It's a separate module, so
importing it doesn't bring in the server's dependencies, and it follows semantic versioning on its
own release line. Its major version tracks the API's `/api/vN`.

```sh
go get github.com/pfenerty/ocidex/pkg/client
```
