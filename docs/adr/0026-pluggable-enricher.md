# ADR 0026: Pluggable Enricher Interface

**Status:** Accepted  
**Date:** 2026-06-06

## Context

After SBOM ingestion, OCIDex needs to fetch or derive additional metadata (OCI image labels, architecture, build info, etc.). The enrichment sources differ in their applicability (e.g., OCI metadata only makes sense for container images) and may grow over time. Hardcoding enrichment logic in the SBOM ingest path would couple unrelated concerns and complicate testing.

## Decision

A plugin registry pattern is used. Each enrichment source implements the `Enricher` interface and self-describes when it applies. A `Dispatcher` dispatches enrichment requests to all registered enrichers that report they can handle the subject.

### Interface

```go
// internal/enrichment/enrichment.go
type Enricher interface {
    Name()       string                                        // unique identifier stored in enrichment.enricher_name
    CanEnrich(ref SubjectRef) bool                            // filter: does this enricher apply?
    Enrich(ctx context.Context, ref SubjectRef) ([]byte, error) // fetch/derive; return JSON bytes
}
```

`SubjectRef` carries the SBOM identity plus artifact metadata (type, name, digest, architecture, build date). It is the only input enrichers receive; they must not import service or repository packages.

### Registration

Both entrypoints register enrichers at startup before the first message is consumed:

```go
// cmd/enrichment-worker/main.go
enrichReg.Register(ocimeta.NewEnricher(ociClient))
enrichReg.Register(userenricher.NewEnricher())
```

The `Dispatcher` iterates all registered enrichers on each request, calling `CanEnrich` then `Enrich` for matching ones. Results are upserted to the `enrichment` table keyed by `(sbom_id, enricher_name)`.

### Sufficiency Promotion

After each enricher runs, the dispatcher checks whether the SBOM now has enough data to be marked `enrichment_sufficient`. Currently the promotion gate checks for the presence of `oci-metadata` and `user` enricher results with non-empty `imageVersion` and `architecture`. If a new enricher also determines sufficiency, add its `Name()` to the check in `internal/enrichment/dispatcher.go:processSubject`.

## Consequences

- Adding a new enricher requires: (1) implement the interface in `internal/enrichment/<name>/`, (2) register in both `cmd/enrichment-worker/main.go` and `cmd/ocidex/main.go` (if the API itself needs inline enrichment). No framework changes.
- `CanEnrich` keeps enrichers from running on irrelevant subjects without any central routing table.
- The interface is intentionally narrow; enrichers that need external HTTP calls own their own client wiring.

## Key Files

- `internal/enrichment/enrichment.go` — `Enricher` interface, `SubjectRef`, `Store` interface
- `internal/enrichment/dispatcher.go` — `Dispatcher`, registration, `processSubject`
- `internal/enrichment/oci/` — built-in OCI metadata enricher
- `cmd/enrichment-worker/main.go` — registration entrypoint
- `docs/DEVELOPMENT.md` — "Adding a New Enricher" section
