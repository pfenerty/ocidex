-- +goose Up

-- Store the container image digest (sha256:...) for lookup by digest.
ALTER TABLE sbom ADD COLUMN digest TEXT;

CREATE INDEX idx_sbom_digest ON sbom (digest) WHERE digest IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_digest;
ALTER TABLE sbom DROP COLUMN IF EXISTS digest;
