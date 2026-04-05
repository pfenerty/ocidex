-- +goose Up
CREATE INDEX IF NOT EXISTS idx_component_license_license_id ON component_license(license_id);
CREATE INDEX IF NOT EXISTS idx_sbom_digest ON sbom(digest) WHERE digest IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_digest;
DROP INDEX IF EXISTS idx_component_license_license_id;
