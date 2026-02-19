---
status: "accepted"
date: 2025-02-06
decision-makers: Patrick Fenerty
---

# Use PostgreSQL as the Database Engine

## Context and Problem Statement

OCIDex needs persistent storage for SBOMs and artifact metadata. The schema is deeply relational (artifacts → packages → versions → licenses) and must be extensible for future report types (e.g., SAST). Which database engine should we use?

## Decision Drivers

* Deep relational schema with foreign keys, CTEs, and complex joins
* JSON support for semi-structured SBOM data
* Full-text search for package/license lookup
* Strong Go driver ecosystem
* Appropriate operational complexity for moderate scale
* Extensibility for future data types

## Considered Options

* PostgreSQL
* SQLite
* CockroachDB

## Decision Outcome

Chosen option: "PostgreSQL", because it provides the best combination of relational depth, JSON support (`jsonb`), built-in full-text search, and Go driver ecosystem maturity. It is right-sized for the project's scale.

### Consequences

* Good, because full SQL compliance — foreign keys, CTEs, window functions, recursive queries
* Good, because `jsonb` with GIN indexing for semi-structured SBOM metadata
* Good, because built-in full-text search (`tsvector`/`tsquery`) avoids a separate search engine
* Good, because `pgx` is the most mature Go database driver
* Neutral, because requires a running server process (Docker Compose for dev)
* Bad, because more operational complexity than SQLite

### Confirmation

Confirmed by successful connection and schema migration in development environment. Repository layer uses PostgreSQL-specific features (jsonb, full-text search) where beneficial.

## Pros and Cons of the Options

### PostgreSQL

* Good, because full relational depth — foreign keys, CTEs, window functions, partial indexes
* Good, because `jsonb` type with GIN indexing for flexible metadata storage
* Good, because built-in full-text search sufficient for moderate scale
* Good, because best Go driver ecosystem (`pgx`)
* Neutral, because medium operational complexity, well-understood
* Bad, because requires server process and connection management

### SQLite

* Good, because zero operational complexity — single file, no server
* Good, because excellent for development and testing
* Bad, because single-writer constraint limits concurrency
* Bad, because limited DDL (no `ALTER COLUMN`)
* Bad, because weaker full-text search and JSON support than PostgreSQL
* Bad, because migration to a different engine later has real cost

### CockroachDB

* Good, because horizontal write scaling and multi-region support
* Good, because PostgreSQL wire-compatible, uses `pgx`
* Bad, because solves scaling problems OCIDex does not have
* Bad, because weaker full-text search — would need external search engine
* Bad, because high operational complexity (3-node minimum for production)

## More Information

* [pgx - PostgreSQL driver for Go](https://github.com/jackc/pgx)
* [PostgreSQL JSON types](https://www.postgresql.org/docs/current/datatype-json.html)
* [PostgreSQL Full-Text Search](https://www.postgresql.org/docs/current/textsearch.html)
