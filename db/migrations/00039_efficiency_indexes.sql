-- +goose NO TRANSACTION
-- Efficiency indexes for large-graph reads and search. CONCURRENTLY (and thus
-- NO TRANSACTION) so building these against a populated production table does
-- not block writes. All are IF NOT EXISTS / IF EXISTS so the migration is
-- idempotent even though it cannot run in a transaction.

-- +goose Up

-- Dependency-graph traversal. Edges join dependency.ref/depends_on against
-- component.bom_ref within an SBOM. Only (sbom_id, ref) existed; the reverse
-- edge (depends_on) and the component-side lookup (bom_ref) were unindexed, so
-- building or walking a dep tree did sequential scans.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dependency_sbom_depends_on
    ON dependency (sbom_id, depends_on);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_sbom_bom_ref
    ON component (sbom_id, bom_ref) WHERE bom_ref IS NOT NULL;

-- Per-SBOM component listing. ListSBOMComponents/ListSBOMPackages filter by
-- sbom_id and ORDER BY name, group_name; idx_component_sbom_id covered only the
-- filter, leaving a separate sort step. This composite serves both.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_sbom_name_group
    ON component (sbom_id, name, group_name);

-- Fuzzy search. SearchDistinctComponents and ListLicenses match name ILIKE
-- '%x%'; a leading wildcard cannot use a btree index, forcing a full scan.
-- Trigram GIN indexes make these sargable.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_name_trgm
    ON component USING gin (name gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_license_name_trgm
    ON license USING gin (name gin_trgm_ops);

-- purl_type. The expression split_part(replace(purl,'pkg:',''),'/',1) is used
-- to both filter and DISTINCT in SearchDistinctComponents / ListComponentPurlTypes;
-- an expression index makes it index-resolvable instead of recomputed per row.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_purl_type
    ON component ((split_part(replace(purl, 'pkg:', ''), '/', 1)))
    WHERE purl IS NOT NULL;

-- Keyset pagination support for ListSBOMs (ORDER BY created_at DESC, id DESC).
-- Supersedes the created_at-only idx_sbom_created_at (created_at leads, so all
-- its uses are still covered).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sbom_created_at_id
    ON sbom (created_at, id);
DROP INDEX CONCURRENTLY IF EXISTS idx_sbom_created_at;

-- Redundant duplicate indexes: the UNIQUE constraints on session.token_hash and
-- api_key.key_hash already create btree indexes; these explicit ones duplicate them.
DROP INDEX CONCURRENTLY IF EXISTS session_token_hash_idx;
DROP INDEX CONCURRENTLY IF EXISTS api_key_key_hash_idx;

-- +goose Down

CREATE INDEX IF NOT EXISTS api_key_key_hash_idx ON api_key (key_hash);
CREATE INDEX IF NOT EXISTS session_token_hash_idx ON session (token_hash);
CREATE INDEX IF NOT EXISTS idx_sbom_created_at ON sbom (created_at);
DROP INDEX CONCURRENTLY IF EXISTS idx_sbom_created_at_id;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_purl_type;
DROP INDEX CONCURRENTLY IF EXISTS idx_license_name_trgm;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_name_trgm;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_sbom_name_group;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_sbom_bom_ref;
DROP INDEX CONCURRENTLY IF EXISTS idx_dependency_sbom_depends_on;
