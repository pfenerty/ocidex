---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use Standard Library Error Handling with Custom API Error Types

## Context and Problem Statement

OCIDex needs consistent API error responses with proper HTTP status codes, and a clean internal error propagation pattern. Which error handling strategy should we use?

## Decision Drivers

* Zero dependencies
* Idiomatic Go — `fmt.Errorf`, `errors.Is`, `errors.As`
* Clean mapping from domain errors to HTTP status codes
* Structured JSON error responses
* Multi-error support for validation (collect all field errors)

## Considered Options

* Standard library error wrapping + custom APIError type
* cockroachdb/errors
* hashicorp/go-multierror

## Decision Outcome

Chosen option: "Standard library error wrapping + custom APIError type", because it is zero-dependency, fully idiomatic, and the custom type pattern cleanly maps domain errors to HTTP responses. `errors.Join` (Go 1.20+) covers the multi-error case for validation.

### Consequences

* Good, because zero dependencies
* Good, because `errors.Is`/`errors.As` for error classification at handler boundaries
* Good, because `errors.Join` for collecting multiple validation errors
* Good, because custom `APIError` type maps cleanly to HTTP status + JSON response
* Good, because stack traces are a logging concern handled by slog context, not error wrapping
* Neutral, because requires defining sentinel errors and error types in the service layer

### Confirmation

Confirmed by verifying all HTTP error responses go through a single error-handling helper or middleware that uses `errors.As` to extract `APIError` types. No ad-hoc `http.Error` calls with hardcoded messages scattered across handlers.

## Pros and Cons of the Options

### Standard library + custom APIError type

* Good, because zero dependencies
* Good, because idiomatic Go patterns (`%w`, `errors.Is`, `errors.As`)
* Good, because `errors.Join` covers multi-error aggregation (Go 1.20+)
* Good, because full control over error structure and JSON serialization
* Neutral, because requires defining sentinel errors (`ErrNotFound`, `ErrConflict`, etc.)

### cockroachdb/errors

* Good, because stack traces on wrap, safe/unsafe detail separation
* Bad, because ~15+ transitive dependencies
* Bad, because features (protobuf encoding, telemetry keys) solve distributed system problems OCIDex does not have
* Bad, because adds nothing for HTTP status mapping — still requires custom types

### hashicorp/go-multierror

* Good, because purpose-built multi-error accumulation
* Bad, because superseded by `errors.Join` in Go 1.20+
* Bad, because effectively in maintenance mode
* Bad, because adds a dependency for stdlib-available functionality

## More Information

* Pattern: define `APIError` with `Code int`, `Message string`, `Err error`. Service layer wraps with sentinel errors. API layer uses `errors.As(&apiErr)` to extract status codes. Single error-handling helper ensures consistent JSON output.
* Depends on: [ADR-0003 (slog)](0003-structured-logging.md) for contextual error logging.
