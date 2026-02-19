---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use chi as the HTTP Router

## Context and Problem Statement

OCIDex needs an HTTP router for its REST API. The router must support method-based routing, path parameters, route grouping, and middleware composition. The project prioritizes small, composable, idiomatic Go libraries over batteries-included frameworks.

## Decision Drivers

* Must use standard `http.Handler` / `http.HandlerFunc` signatures
* Zero or minimal external dependencies
* Route grouping with per-group middleware (public health checks vs. authenticated API routes)
* Actively maintained
* Composable middleware using the `func(http.Handler) http.Handler` pattern

## Considered Options

* Go 1.22+ stdlib `net/http` (enhanced ServeMux)
* chi (`go-chi/chi/v5`)
* gorilla/mux
* Echo
* Fiber

## Decision Outcome

Chosen option: "chi", because it is zero-dependency, fully `http.Handler` compatible, and provides route grouping and middleware composition that stdlib lacks — without introducing framework coupling.

### Consequences

* Good, because handlers are standard `func(http.ResponseWriter, *http.Request)` — portable and testable with `httptest`
* Good, because any stdlib-compatible middleware works without adapters
* Good, because zero external dependencies
* Good, because route groups enable clean separation of public, API, and future admin routes
* Neutral, because it adds one module dependency to `go.mod` despite having no transitive deps
* Bad, because if Go stdlib adds route grouping in future versions, chi becomes redundant (migration would be straightforward)

### Confirmation

Confirmed by verifying that all route handlers use `http.HandlerFunc` and middleware uses the `func(http.Handler) http.Handler` signature. No chi-specific types should appear in handler signatures.

## Pros and Cons of the Options

### Go 1.22+ stdlib net/http

* Good, because zero dependencies and maximum idiomacy
* Good, because method routing and path parameters now built-in
* Bad, because no route grouping or sub-routers
* Bad, because no middleware chaining — must be hand-rolled
* Bad, because becomes verbose with 20+ routes and multiple middleware stacks

### chi

* Good, because zero external dependencies
* Good, because `http.Handler` native — handlers are standard Go
* Good, because route groups with per-group middleware
* Good, because actively maintained (v5.2.x, Jan 2025)
* Good, because optional middleware package (logging, recoverer, timeout)
* Neutral, because does not handle body parsing or validation (by design)

### gorilla/mux

* Good, because `http.Handler` compatible with regex route constraints
* Bad, because effectively discontinued — archived Dec 2022, minimal activity since revival
* Bad, because no Go 1.22+ integration
* Bad, because linear route matching is slower than radix-tree routers

### Echo

* Good, because high performance and built-in request binding
* Bad, because custom `echo.HandlerFunc` signature couples handler code to Echo
* Bad, because ~14 transitive dependencies
* Bad, because framework, not a composable library

### Fiber

* Good, because raw throughput performance
* Bad, because built on fasthttp, not `net/http` — incompatible with Go ecosystem
* Bad, because context values are pooled and reused across requests (data race hazard)
* Bad, because ~17 dependencies, no HTTP/2 support
* Bad, because fundamentally non-idiomatic Go

## More Information

* [go-chi/chi](https://github.com/go-chi/chi)
* [Go 1.22 routing enhancements](https://go.dev/blog/routing-enhancements)
