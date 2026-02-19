---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use oapi-codegen for Spec-First API Documentation

## Context and Problem Statement

OCIDex needs API documentation that stays in sync with the implementation. How should the API contract be defined and shared?

## Decision Drivers

* Spec-to-code accuracy — drift between documentation and implementation must be prevented
* No framework coupling — generated code should use `net/http` / chi handlers
* Minimal runtime dependencies
* Small, composable tooling — not a framework
* OpenAPI 3.x output for standard tooling compatibility

## Considered Options

* oapi-codegen (spec-first)
* swaggo/swag (code-first annotations)
* Hand-written OpenAPI spec
* huma (code-first framework)

## Decision Outcome

Chosen option: "oapi-codegen", because it enforces spec-code sync at compile time via generated interfaces, produces `net/http`-compatible code with zero runtime dependencies, and keeps the OpenAPI spec as the single source of truth.

### Consequences

* Good, because compile-time enforcement — handlers must implement the generated interface
* Good, because zero runtime dependencies — generated code is plain Go
* Good, because generated code targets chi directly (supported output target)
* Good, because OpenAPI 3.x spec is the single source of truth
* Good, because spec can be shared with consumers before implementation
* Neutral, because requires writing OpenAPI YAML first — upfront friction that pays off as the API grows
* Bad, because runtime behavior (wrong status codes, missing headers) is not caught by the generated interface

### Confirmation

Confirmed by verifying the generated server interface is implemented by the API handler struct and that `oapi-codegen` runs in CI. Any spec change that breaks the interface causes a compile error.

## Pros and Cons of the Options

### oapi-codegen (spec-first)

* Good, because compile-time spec-code sync via generated interfaces
* Good, because zero runtime dependencies
* Good, because targets net/http, chi, echo, etc. — we use chi
* Good, because actively maintained (v2, 2024)
* Neutral, because YAML-first workflow has learning curve
* Bad, because complex specs produce verbose generated code

### swaggo/swag (code-first annotations)

* Good, because no spec file to maintain separately
* Bad, because primary output is Swagger 2.0 — OpenAPI 3.0 is experimental
* Bad, because comments can drift from handler behavior silently
* Bad, because annotation syntax is brittle and pollutes godoc
* Bad, because no compile-time enforcement of accuracy

### Hand-written OpenAPI spec

* Good, because zero dependencies, full control
* Bad, because no enforcement of spec-code sync — drift is inevitable
* Bad, because high maintenance burden as API grows
* Bad, because all the cost of writing OpenAPI with none of the automation benefits

### huma (code-first framework)

* Good, because spec generated automatically from Go structs at runtime
* Good, because strong spec-code sync — spec IS the code
* Bad, because framework coupling — handlers must use huma's signature, not `http.HandlerFunc`
* Bad, because single-maintainer risk
* Bad, because contradicts "small, composable, idiomatic" principle

## More Information

* [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen)
* Depends on: [ADR-0002 (chi)](0002-http-router.md) — oapi-codegen generates chi-compatible server code.
