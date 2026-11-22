-- +goose NO TRANSACTION
-- A finding can be published against a component's source package (a Debian
-- binary package's source, say) rather than the component's own purl, so the
-- set of purls an SBOM is matched on is purl ∪ source_purl. The SBOM and
-- artifact counts already used that union; the cluster, vulnerability-detail
-- and discover counts joined on purl alone and missed those findings.
--
-- sbom_match_scope() is that union for one SBOM, for queries that start from
-- an SBOM. Queries that start from a vulnerability look components up by
-- source_purl as well as purl, which is what the index is for.

-- +goose Up

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_source_purl
    ON component (source_purl) WHERE source_purl IS NOT NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sbom_match_scope(s_id UUID)
RETURNS TABLE (purl TEXT, go_symbol_set_id BIGINT)
LANGUAGE sql
STABLE
AS $$
  SELECT c1.purl::text, COALESCE(c1.go_symbol_set_id, 0)::bigint
  FROM component c1 WHERE c1.sbom_id = s_id AND c1.purl IS NOT NULL
  UNION
  SELECT c2.source_purl::text, 0::bigint
  FROM component c2 WHERE c2.sbom_id = s_id AND c2.source_purl IS NOT NULL
$$;
-- +goose StatementEnd

-- The other direction: every component a vulnerability (by canonical id, so
-- across its aliases) matches, through the component's purl or its source
-- purl, with the fixed version that match carries. A component matched both
-- ways appears twice; callers aggregate with DISTINCT.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION affected_by_canonical(canonical TEXT)
RETURNS TABLE (component_id UUID, fixed_version TEXT)
LANGUAGE sql
STABLE
AS $$
  SELECT c.id, pv.fixed_version
  FROM vulnerability v
  JOIN package_vulnerability pv ON pv.vulnerability_id = v.id
  JOIN component c ON c.purl = pv.purl AND COALESCE(c.go_symbol_set_id, 0) = pv.go_symbol_set_id
  WHERE v.canonical_id = canonical
  UNION ALL
  SELECT c.id, pv.fixed_version
  FROM vulnerability v
  JOIN package_vulnerability pv ON pv.vulnerability_id = v.id AND pv.go_symbol_set_id = 0
  JOIN component c ON c.source_purl = pv.purl
  WHERE v.canonical_id = canonical
$$;
-- +goose StatementEnd

-- +goose Down

DROP FUNCTION IF EXISTS affected_by_canonical(TEXT);
DROP FUNCTION IF EXISTS sbom_match_scope(UUID);
DROP INDEX CONCURRENTLY IF EXISTS idx_component_source_purl;
