-- +goose NO TRANSACTION

-- Drop three component indexes no query uses (ocidex-kf1p.6). Together they are
-- ~16 GB that every ingest writes to and that compete with the request path for
-- a 1.5 GB shared_buffers. Each recorded zero scans in pg_stat_user_indexes on
-- ocidex-dev, and each is unused by construction, not just by observation:
--
-- idx_component_sbom_name_group (sbom_id, name, group_name), 8.1 GB, is an exact
-- prefix of idx_component_sbom_pkg_identity (sbom_id, name, group_name, type)
-- from 00047, which serves the same per-SBOM filter and name ordering.
--
-- idx_component_sbom_bom_ref (sbom_id, bom_ref), 4.7 GB, was for walking the
-- dependency graph in SQL. The graph is resolved in Go from
-- ListDependenciesBySBOM and the SBOM's component list, and no query looks a
-- component up by bom_ref value.
--
-- idx_component_name_trgm, 3.2 GB, backed `component.name ILIKE` in
-- SearchDistinctComponents. That query reads component_rollup since ocidex-ckv.2,
-- which has its own trigram index (00077). Nothing else matches component names
-- by pattern.
--
-- CONCURRENTLY, as 00039 built them: a plain DROP INDEX takes ACCESS EXCLUSIVE
-- on component and would stall every read of it for the duration.

-- +goose Up
DROP INDEX CONCURRENTLY IF EXISTS idx_component_sbom_name_group;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_sbom_bom_ref;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_name_trgm;

-- +goose Down
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_name_trgm
    ON component USING gin (name gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_sbom_bom_ref
    ON component (sbom_id, bom_ref) WHERE bom_ref IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_sbom_name_group
    ON component (sbom_id, name, group_name);
