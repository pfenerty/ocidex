---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use log/slog for Structured Logging

## Context and Problem Statement

OCIDex needs structured, leveled logging across the application — in middleware, service logic, and repository operations. Which logging library should we use?

## Decision Drivers

* Zero or minimal dependencies
* Idiomatic Go, stdlib-aligned
* Context-aware logging (request IDs, trace context)
* Sufficient performance for moderate scale
* Ecosystem convergence — avoid adopting something the ecosystem is moving away from

## Considered Options

* log/slog (stdlib)
* rs/zerolog
* uber-go/zap

## Decision Outcome

Chosen option: "log/slog", because it is zero-dependency, context-aware by design, and the direction the Go ecosystem is converging toward. If performance becomes insufficient, zerolog or zap can be plugged in as a `slog.Handler` backend without changing call sites.

### Consequences

* Good, because zero dependencies
* Good, because native `context.Context` integration via `InfoContext`, `ErrorContext`
* Good, because `slog.Handler` interface allows swapping backends later without changing application code
* Good, because every Go developer knows stdlib patterns
* Neutral, because performance is adequate but not best-in-class (zerolog is faster)
* Bad, because no built-in chi middleware — requires a small custom middleware or community package

### Confirmation

Confirmed by verifying all logging call sites use `slog` (not direct `log` or `fmt.Print`). Logging middleware should inject request-scoped attributes into context.

## Pros and Cons of the Options

### log/slog

* Good, because zero dependencies — part of stdlib since Go 1.21
* Good, because context-first design (`InfoContext(ctx, ...)`)
* Good, because `slog.Handler` interface enables backend swaps
* Good, because ecosystem is converging on slog as the logging facade
* Neutral, because adequate but not fastest performance
* Bad, because no official chi middleware (trivial to write)

### rs/zerolog

* Good, because fastest performance (zero-allocation)
* Good, because minimal dependencies (2 direct)
* Good, because built-in `hlog` middleware for chi-compatible routers
* Bad, because fluent/builder API is unusual for Go
* Bad, because does not implement `slog.Handler` natively
* Bad, because tightly coupled to JSON output format

### uber-go/zap

* Good, because very fast, production-hardened at Uber scale
* Good, because implements `slog.Handler` since v1.27
* Bad, because 8+ transitive dependencies (heaviest option)
* Bad, because dual API (Logger vs SugaredLogger) adds cognitive overhead
* Bad, because context support is bolted on, not native

## More Information

* [log/slog package docs](https://pkg.go.dev/log/slog)
* [slog proposal](https://go.dev/blog/slog)
