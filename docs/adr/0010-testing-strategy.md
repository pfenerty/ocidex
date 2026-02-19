---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use matryer/is for Unit Tests and testcontainers-go for Integration Tests

## Context and Problem Statement

OCIDex needs a testing strategy covering unit tests (handlers, services, repositories), HTTP layer tests, and integration tests against PostgreSQL. Which tools should we use?

## Decision Drivers

* Minimal dependencies in production code — test deps are acceptable
* Table-driven tests as the standard pattern
* Manual interface fakes over generated mocks (interfaces are small)
* Real PostgreSQL for integration tests, not mocks
* Clean failure output with diffs

## Considered Options

* stdlib testing + httptest
* stretchr/testify
* matryer/is
* testcontainers-go (for integration tests)

## Decision Outcome

Chosen option: "matryer/is for unit tests, testcontainers-go for integration tests, stdlib httptest for HTTP layer", because this combination provides clean assertions with zero production dependencies, real database testing, and no framework coupling.

### Consequences

* Good, because `matryer/is` has zero dependencies and minimal API (~4 methods)
* Good, because table-driven tests work identically to stdlib
* Good, because testcontainers-go provides real PostgreSQL for integration tests
* Good, because `httptest` from stdlib covers HTTP handler testing
* Good, because manual fakes keep tests simple and type-safe
* Neutral, because testcontainers-go has ~30 transitive deps (isolated to test builds)
* Bad, because testcontainers-go requires Docker daemon in CI

### Confirmation

Confirmed by verifying: unit tests use `is.Equal`/`is.NoErr` (not testify), integration tests in `tests/` use testcontainers for PostgreSQL, and no mock generation tools are in the build pipeline. CI runs Docker for integration tests.

## Pros and Cons of the Options

### stdlib testing + httptest

* Good, because zero dependencies
* Good, because maximum idiomatic Go
* Bad, because verbose assertions — manual `if got != want { t.Errorf(...) }`
* Bad, because no diff output on failure

### stretchr/testify

* Good, because rich diff output, widely used
* Bad, because ~4 transitive dependencies
* Bad, because `testify/mock` is stringly-typed and encourages over-mocking
* Bad, because `suite` package adds unneeded xUnit lifecycle

### matryer/is

* Good, because zero dependencies
* Good, because minimal API surface (~4 methods: `Equal`, `NoErr`, `True`, `Fail`)
* Good, because color diff output on failure
* Good, because designed to feel like stdlib with less boilerplate
* Neutral, because no deep-equal customization (add `go-cmp` if needed later)

### testcontainers-go

* Good, because real PostgreSQL container with lifecycle management
* Good, because dedicated Postgres module handles image, wait strategies, init scripts
* Good, because `t.Cleanup` integration for automatic teardown
* Bad, because heavy dependency tree (~30 transitive) — justified only in test builds
* Bad, because requires Docker daemon, adds 10-30s startup per container

## More Information

* [matryer/is](https://github.com/matryer/is)
* [testcontainers-go](https://github.com/testcontainers/testcontainers-go)
* [net/http/httptest](https://pkg.go.dev/net/http/httptest)
