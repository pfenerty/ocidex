-- +goose Up
CREATE INDEX idx_sbom_created_at ON sbom (created_at);

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_created_at;
