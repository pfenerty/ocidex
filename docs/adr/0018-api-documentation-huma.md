---
status: "accepted"
date: 2025-02-19
decision-makers: Patrick Fenerty
supersedes: 0011-api-documentation.md
---

# Use huma for Code-First API Documentation

## Context and Problem Statement

OCIDex needs API documentation that stays in sync with the implementation. ADR-0011 chose oapi-codegen (spec-first), but it was never implemented — the API currently uses plain chi handlers with manual JSON encoding and no OpenAPI spec. The upfront friction of writing OpenAPI YAML before code has prevented adoption.

How should the API contract be defined, documented, and kept in sync with the implementation?

## Decision Drivers

* Spec-to-code accuracy — drift between documentation and implementation must be prevented
* Low adoption friction — the approach must work incrementally on an existing codebase
* Minimal boilerplate — reduce repetitive JSON encoding, error handling, and validation code
* OpenAPI 3.1 output for standard tooling compatibility
* chi compatibility — must work with the existing chi router and middleware stack

## Considered Options

* oapi-codegen (spec-first) — previous decision, never implemented
* huma v2 (code-first framework with chi adapter)

## Decision Outcome

Chosen option: "huma v2", because it generates an accurate OpenAPI 3.1 spec directly from Go handler signatures and struct tags, requires zero upfront YAML authoring, integrates with chi via the humachi adapter, and replaces manual JSON encoding/error handling with typed inputs and outputs.

This supersedes ADR-0011.

### Consequences

* Good, because spec IS the code — OpenAPI spec is generated from Go types at startup, eliminating drift
* Good, because chi middleware stack is preserved — huma wraps the existing chi router
* Good, because validation, content negotiation, and error responses are handled automatically
* Good, because RFC 7807 problem details replace ad-hoc error JSON, improving API consistency
* Good, because built-in docs UI served at `/docs` with no additional tooling
* Good, because incremental adoption — huma operations coexist with raw chi routes during migration
* Neutral, because handler signatures change from `func(w, r)` to `func(ctx, *Input) (*Output, error)` — all handler tests must be updated
* Bad, because error response shape changes from `{"error":"..."}` to RFC 7807 `{"status":N,"title":"...","detail":"..."}` — frontend error handling must be updated
* Bad, because adds a runtime dependency (huma) to the request path

### Confirmation

Confirmed by verifying that `GET /openapi.json` returns a valid OpenAPI 3.1 spec containing all registered operations, and that the generated spec matches actual handler behavior (status codes, request/response schemas).

## Pros and Cons of the Options

### oapi-codegen (spec-first)

* Good, because compile-time spec-code sync via generated interfaces
* Good, because zero runtime dependencies
* Bad, because requires writing OpenAPI YAML upfront — proven friction that blocked adoption
* Bad, because runtime behavior (wrong status codes, missing headers) is not caught by the generated interface
* Bad, because verbose generated code for complex specs

### huma v2 (code-first)

* Good, because spec generated from Go types — no YAML to author or maintain
* Good, because typed handler signatures enforce request/response contracts at compile time
* Good, because automatic input validation from struct tags (required, min, max, enum, pattern)
* Good, because built-in RFC 7807 error model replaces custom error types
* Good, because chi adapter preserves existing middleware and routing
* Good, because actively maintained with broad adoption
* Bad, because framework coupling — handlers use huma's signature, not raw `http.HandlerFunc`
* Bad, because breaking change to error response format

## More Information

* [huma v2](https://huma.rocks/)
* [humachi adapter](https://github.com/danielgtaylor/huma/tree/main/adapters/humachi)
* Supersedes: [ADR-0011 (oapi-codegen)](0011-api-documentation.md)
* Depends on: [ADR-0002 (chi)](0002-http-router.md) — huma wraps the chi router via humachi adapter