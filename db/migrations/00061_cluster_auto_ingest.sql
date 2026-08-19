-- +goose Up
ALTER TABLE cluster ADD COLUMN auto_ingest BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN cluster.auto_ingest IS
    'When true, an accepted inventory snapshot submits scan jobs for every running image with no SBOM whose host resolves to a registry in this cluster''s namespace (ADR-044). Defaults to true: a cluster that reports what it runs and then leaves it unscanned is the gap the inventory exists to close. Resolution never leaves the namespace — using another namespace''s registry would pull with credentials this cluster was never granted.';

-- +goose Down
ALTER TABLE cluster DROP COLUMN auto_ingest;
