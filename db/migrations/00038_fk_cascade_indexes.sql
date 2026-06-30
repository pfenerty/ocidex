-- +goose Up
-- Postgres does not auto-create indexes on foreign-key columns. Deleting an SBOM
-- cascades to its components, and each component delete cascades again via the
-- self-referential component.parent_id FK; without an index that is a sequential
-- scan of the whole component table per row, so a single SBOM delete took minutes.
-- scan_jobs.sbom_id (SET NULL when its SBOM is deleted) and registry.owner_id
-- (SET NULL when its owner is deleted) have the same unindexed-FK problem.
--
-- Partial (WHERE NOT NULL) because these columns are NULL for most rows
-- (top-level components, unlinked scan_jobs, ownerless registries); the cascade
-- only ever looks up non-null values, so the partial index fully serves it.
CREATE INDEX IF NOT EXISTS idx_component_parent_id ON component (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_jobs_sbom_id ON scan_jobs (sbom_id) WHERE sbom_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_registry_owner_id ON registry (owner_id) WHERE owner_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_registry_owner_id;
DROP INDEX IF EXISTS idx_scan_jobs_sbom_id;
DROP INDEX IF EXISTS idx_component_parent_id;
