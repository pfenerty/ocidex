-- +goose Up
ALTER TABLE enrichment_jobs ADD COLUMN enricher_name TEXT NOT NULL DEFAULT 'all';
ALTER TABLE enrichment_jobs ADD CONSTRAINT enrichment_jobs_sbom_enricher_unique UNIQUE (sbom_id, enricher_name);
CREATE INDEX idx_enrichment_jobs_enricher_queued ON enrichment_jobs (enricher_name, created_at) WHERE state = 'queued';

-- +goose Down
DROP INDEX IF EXISTS idx_enrichment_jobs_enricher_queued;
ALTER TABLE enrichment_jobs DROP CONSTRAINT IF EXISTS enrichment_jobs_sbom_enricher_unique;
ALTER TABLE enrichment_jobs DROP COLUMN IF EXISTS enricher_name;
