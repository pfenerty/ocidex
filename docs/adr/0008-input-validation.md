---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use Custom Validation for Input Validation

## Context and Problem Statement

OCIDex needs to validate incoming CycloneDX JSON payloads and request parameters. Which validation approach should we use?

## Decision Drivers

* Zero dependencies preferred
* Compile-time safety — validation logic should be explicit Go code, not magic strings
* Composable with the interface-based architecture
* CycloneDX has a well-defined, bounded schema — validation surface is manageable
* Consistent, JSON-serializable error output for API responses

## Considered Options

* go-playground/validator
* go-ozzo/ozzo-validation
* Custom validation (hand-written)

## Decision Outcome

Chosen option: "Custom validation", because the validation surface is bounded (CycloneDX schema), zero dependencies is achievable, and explicit Go code with `Validate() error` methods aligns with the project's interface-based design. No reflection, no tags, no magic.

### Consequences

* Good, because zero dependencies
* Good, because validation logic is explicit, testable Go code
* Good, because `Validate() error` methods compose with interface-based design
* Good, because full control over error structure and JSON serialization
* Neutral, because more boilerplate than a tag-based library
* Bad, because repetitive checks (required, length, format) must be written manually — consider small internal helpers

### Confirmation

Confirmed by verifying all request types implement a `Validate() error` method and that validation errors are returned as structured JSON (not raw strings). No reflection-based validation in the codebase.

## Pros and Cons of the Options

### go-playground/validator

* Good, because low boilerplate via struct tags
* Good, because actively maintained, widely used
* Bad, because struct tags are magic strings with no compile-time checking
* Bad, because 5 direct dependencies
* Bad, because human-readable error messages require translator boilerplate
* Bad, because tag DSL grows complex for conditional/cross-field rules

### go-ozzo/ozzo-validation

* Good, because code-based rules with compile-time checking
* Good, because JSON-serializable errors out of the box
* Good, because minimal dependencies (2 direct)
* Bad, because stalled maintenance — last meaningful commit ~2022
* Bad, because no stable v4 release

### Custom validation

* Good, because zero dependencies
* Good, because explicit, testable, fully composable Go code
* Good, because full control over error types and serialization
* Good, because `Validate() error` pattern fits interface-based architecture
* Bad, because boilerplate for repetitive checks (mitigated with small internal helpers)

## More Information

* Pattern: each domain type implements `Validate() error`, returning a structured `ValidationError` (map of field → messages) that serializes to JSON for API responses.
* If validation complexity grows significantly, revisit with ozzo-validation (if maintenance resumes) or a similar code-based library.
