---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use sqlc with pgx for Database Access

## Context and Problem Statement

OCIDex needs a Go interface to PostgreSQL for a deeply relational schema (artifacts, packages, versions, licenses). Which database driver and query approach should we use?

## Decision Drivers

* Compile-time type safety for SQL queries
* Full SQL control — no ORM query limitations for complex joins and CTEs
* Minimal runtime dependencies
* Small, composable — not a framework
* Performance equivalent to hand-written code
* Fits the layered architecture (generated code behind repository interfaces)

## Considered Options

* database/sql + pgx (stdlib mode)
* pgx native (direct)
* sqlx
* sqlc + pgx native
* GORM
* ent

## Decision Outcome

Chosen option: "sqlc + pgx native", because sqlc generates type-safe Go code from SQL queries validated against the schema, with zero runtime overhead beyond pgx itself. SQL stays SQL, Go stays Go — no DSL, no reflection, no framework.

### Consequences

* Good, because compile-time validation of queries against the schema
* Good, because generated code is functionally identical to hand-written pgx code
* Good, because full SQL control — writes, CTEs, window functions, anything PostgreSQL supports
* Good, because generated `Queries` struct maps cleanly to repository interfaces
* Good, because schema `.sql` files are the single source of truth
* Neutral, because requires a `sqlc generate` step in the build workflow
* Bad, because joined query results produce flat structs — relation mapping is manual in the service layer

### Confirmation

Confirmed by verifying `sqlc generate` runs without errors in CI and that all repository implementations use generated query functions. No raw SQL string construction in application code.

## Pros and Cons of the Options

### database/sql + pgx (stdlib mode)

* Good, because maximum stdlib idiomacy
* Bad, because manual `rows.Scan` — column/type mismatches are runtime errors
* Bad, because ~10-30% slower than native pgx (interface abstraction overhead)
* Bad, because no batch/pipeline support

### pgx native (direct)

* Good, because best-in-class Go+Postgres performance
* Good, because batch queries, COPY protocol, prepared statement caching
* Bad, because manual scanning and type matching — all runtime errors
* Bad, because significant boilerplate for a deep schema

### sqlx

* Good, because struct scanning reduces boilerplate over raw database/sql
* Bad, because stalled maintenance — last meaningful commit 2022
* Bad, because still runtime type checking, not compile-time

### sqlc + pgx native

* Good, because compile-time type safety — schema changes that break queries are caught at generation time
* Good, because zero runtime overhead beyond pgx
* Good, because you write real SQL — full PostgreSQL feature access
* Good, because generated code is readable, auditable, idiomatic Go
* Good, because `sqlc.embed()` for composing model structs in query results
* Neutral, because requires code generation step
* Bad, because flat struct output for joins — manual relation mapping needed

### GORM

* Good, because low boilerplate for simple CRUD
* Bad, because heavy reflection, 2-5x slower than raw pgx
* Bad, because string-based column references — runtime errors
* Bad, because generates suboptimal SQL for complex queries, easy N+1 problems
* Bad, because batteries-included framework contradicts project principles

### ent

* Good, because strong compile-time type safety via code generation
* Good, because excellent for graph-style traversals
* Bad, because framework that owns schema definition, migrations, and query patterns
* Bad, because weak escape hatch for complex SQL (CTEs, window functions)
* Bad, because large generated code volume

## More Information

* [sqlc](https://sqlc.dev/)
* [jackc/pgx](https://github.com/jackc/pgx)
* Depends on: [ADR-0005 (PostgreSQL)](0005-database-engine.md)
