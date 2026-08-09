-- Sunset the legacy monolithic enrichment-worker (ocidex-kg5).
--
-- The per-enricher workers (ADR-033) each claim their own enricher_name
-- partition; nothing has enqueued an 'all' row since the submitter switched to
-- rootEnrichers. Rows are deleted in every state, not just non-terminal ones:
-- succeeded 'all' rows would otherwise linger as a phantom enricher in the
-- admin Jobs page and in SummarizeEnrichmentJobs' per-(enricher, state) matrix.
--
-- Dropping the DEFAULT (added by 00036_per_enricher_jobs.sql) turns a caller
-- that forgets to set enricher_name into a NOT NULL violation instead of a
-- silently mis-partitioned row.

-- +goose Up
DELETE FROM enrichment_jobs WHERE enricher_name = 'all';
ALTER TABLE enrichment_jobs ALTER COLUMN enricher_name DROP DEFAULT;

-- +goose Down
ALTER TABLE enrichment_jobs ALTER COLUMN enricher_name SET DEFAULT 'all';
