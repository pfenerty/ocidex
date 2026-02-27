-- +goose Up
DROP INDEX IF EXISTS idx_sbom_digest;
CREATE UNIQUE INDEX idx_sbom_digest ON sbom (digest) WHERE digest IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_digest;
CREATE INDEX idx_sbom_digest ON sbom (digest) WHERE digest IS NOT NULL;
