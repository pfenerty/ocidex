---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use goose for Schema Migration Management

## Context and Problem Statement

OCIDex needs versioned database migrations for PostgreSQL with rollback support, embeddable as a library, and usable in CI. Which migration tool should we use?

## Decision Drivers

* Minimal dependencies
* SQL migration files as the primary format
* Rollback (down migration) support
* Usable as both a CLI and a Go library (embeddable in application startup)
* Uses `database/sql` — composable with pgx stdlib adapter
* Actively maintained

## Considered Options

* pressly/goose (v3)
* golang-migrate/migrate (v4)
* ariga/atlas

## Decision Outcome

Chosen option: "pressly/goose v3", because it is minimal-dependency, `database/sql` native, embeddable via constructor-based provider, and supports both SQL and Go migrations. It fits naturally into the existing Makefile and DI patterns.

### Consequences

* Good, because minimal dependencies — you bring your own database driver
* Good, because `database/sql` native — composable with pgx stdlib adapter
* Good, because v3 `goose.NewProvider()` fits constructor-based DI
* Good, because supports both SQL and Go function migrations
* Good, because simple CLI for local development (`goose up`, `goose down`)
* Neutral, because SQL migration files serve double duty as sqlc schema input
* Bad, because smaller community than golang-migrate

### Confirmation

Confirmed by verifying migrations run successfully in CI and that `goose.NewProvider()` is used in application startup. Migration files live in a dedicated directory and are the schema source of truth for sqlc.

## Pros and Cons of the Options

### pressly/goose v3

* Good, because minimal dependencies — core has zero non-driver deps
* Good, because `database/sql` native
* Good, because library-first design with constructor-based provider
* Good, because supports SQL and Go function migrations in the same sequence
* Good, because full rollback support
* Good, because actively maintained (v3, 2023+)

### golang-migrate v4

* Good, because widely used (~15k stars), many database drivers
* Bad, because slow maintainer response — PRs can sit for months
* Bad, because does not use `database/sql` directly — wraps its own connection management
* Bad, because plugin-via-import-side-effect pattern is not idiomatic Go
* Bad, because dirty-state handling complicates CI automation
* Bad, because SQL-only — no Go function migrations

### ariga/atlas

* Good, because advanced CI story (schema linting, drift detection)
* Good, because declarative mode computes schema diffs automatically
* Bad, because heavy dependency tree
* Bad, because CLI-first, not library-first
* Bad, because HCL schema language is a DSL outside Go
* Bad, because over-engineered for a single-service API

## More Information

* [pressly/goose](https://github.com/pressly/goose)
* Depends on: [ADR-0005 (PostgreSQL)](0005-database-engine.md), [ADR-0006 (sqlc + pgx)](0006-database-driver.md)
