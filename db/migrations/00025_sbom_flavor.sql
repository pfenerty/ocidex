-- +goose Up

-- Add nullable text column for image flavor (alpine, debian, wolfi, etc.)
-- Populated by the detector in F2; backfilled in F3. Indexed for changelog grouping.
ALTER TABLE sbom ADD COLUMN flavor TEXT;

CREATE INDEX idx_sbom_flavor ON sbom (flavor) WHERE flavor IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_flavor;
ALTER TABLE sbom DROP COLUMN IF EXISTS flavor;
