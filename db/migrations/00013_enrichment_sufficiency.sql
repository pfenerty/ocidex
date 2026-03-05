-- +goose Up
ALTER TABLE sbom ADD COLUMN enrichment_sufficient BOOLEAN NOT NULL DEFAULT false;

-- Backfill existing SBOMs: mark as sufficient if any successful enrichment
-- contains both imageVersion and architecture.
UPDATE sbom s SET enrichment_sufficient = true
WHERE EXISTS (
    SELECT 1 FROM enrichment e
    WHERE e.sbom_id = s.id
      AND e.status = 'success'
      AND e.data->>'imageVersion' IS NOT NULL AND e.data->>'imageVersion' != ''
      AND e.data->>'architecture' IS NOT NULL AND e.data->>'architecture' != ''
);

CREATE INDEX idx_sbom_enrichment_sufficient ON sbom (enrichment_sufficient)
    WHERE enrichment_sufficient = true;

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_enrichment_sufficient;
ALTER TABLE sbom DROP COLUMN IF EXISTS enrichment_sufficient;
