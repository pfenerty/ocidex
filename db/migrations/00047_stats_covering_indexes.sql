-- +goose NO TRANSACTION
-- Covering indexes for the dashboard-stats aggregate queries (ocidex-343).
-- GetSummaryCounts (package_count/version_count), GetPackageGrowthTimeline,
-- GetVersionGrowthTimeline, and GetTopPackagesByVersionCount all GROUP
-- BY/DISTINCT on (sbom_id, name, group_name[, version], type) after joining
-- component to the visible-sbom set; these let that aggregation run as an
-- index-only scan instead of a heap fetch per component row. CONCURRENTLY
-- (and thus NO TRANSACTION) so building against a populated table does not
-- block writes.

-- +goose Up
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_sbom_pkg_identity
    ON component (sbom_id, name, group_name, type);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_sbom_ver_identity
    ON component (sbom_id, name, group_name, version, type);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS idx_component_sbom_ver_identity;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_sbom_pkg_identity;
