-- Per-severity vulnerability counts on component_rollup (ocidex-unn8.10), so
-- /components can be ordered by risk. Computing them per request is the shape
-- ocidex-ckv.2 measured at ~53s against a 30s HTTP timeout, which is why the
-- rollup exists; the counts belong here, not in SearchDistinctComponents.
--
-- Columns are appended after sbom_count on purpose: SwapRollupSnapshots does a
-- positional `INSERT INTO component_rollup SELECT * FROM tmp_component_rollup`,
-- so the live table's column order must match componentRollupAggregate's select
-- list. Appending keeps both in step.
--
-- Unlike sbom_vuln_rollup (00063), component_rollup holds a row for every
-- (namespace, package identity) whether or not it has findings, so zero here
-- means "no known vulnerabilities" and not "never scanned". Readers should
-- render it as a plain zero — the ADR-044 caveat does not apply to this table.
--
-- The backfill below mirrors componentRollupAggregate's severity CTEs, for the
-- same reason 00051 and 00063 seeded their tables: without it the new columns
-- read as all-zero until the first refresher pass.

-- +goose Up

ALTER TABLE component_rollup
    ADD COLUMN critical BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN high     BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN medium   BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN low      BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN unknown  BIGINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN component_rollup.critical IS
    'Distinct canonical vulnerability ids of CRITICAL severity reachable from any version of this package identity in this namespace. A CVE affecting two versions counts once: the row is the identity, not a version.';

-- +goose StatementBegin
WITH scope AS (
    SELECT DISTINCT s1.namespace_id, c1.type, c1.name, c1.group_name,
           c1.purl::text AS match_purl
    FROM component c1
    JOIN sbom s1 ON s1.id = c1.sbom_id
    WHERE c1.purl IS NOT NULL
    UNION
    SELECT DISTINCT s2.namespace_id, c2.type, c2.name, c2.group_name,
           c2.source_purl::text AS match_purl
    FROM component c2
    JOIN sbom s2 ON s2.id = c2.sbom_id
    WHERE c2.source_purl IS NOT NULL
), findings AS (
    SELECT DISTINCT sc.namespace_id, sc.type, sc.name, sc.group_name,
           v.canonical_id, v.severity
    FROM scope sc
    JOIN package_vulnerability pv ON pv.purl = sc.match_purl
    JOIN vulnerability v ON v.id = pv.vulnerability_id
), sev AS (
    SELECT f.namespace_id, f.type, f.name, f.group_name,
           count(*) FILTER (WHERE f.severity = 'CRITICAL')::bigint AS critical,
           count(*) FILTER (WHERE f.severity = 'HIGH')::bigint     AS high,
           count(*) FILTER (WHERE f.severity = 'MEDIUM')::bigint   AS medium,
           count(*) FILTER (WHERE f.severity = 'LOW')::bigint      AS low,
           count(*) FILTER (WHERE f.severity IS NULL
                               OR f.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))::bigint AS unknown
    FROM findings f
    GROUP BY f.namespace_id, f.type, f.name, f.group_name
)
UPDATE component_rollup r
SET critical = sv.critical,
    high     = sv.high,
    medium   = sv.medium,
    low      = sv.low,
    unknown  = sv.unknown
FROM sev sv
WHERE sv.namespace_id = r.namespace_id
  AND sv.type = r.type
  AND sv.name = r.name
  AND sv.group_name IS NOT DISTINCT FROM r.group_name;
-- +goose StatementEnd

-- +goose Down

ALTER TABLE component_rollup
    DROP COLUMN critical,
    DROP COLUMN high,
    DROP COLUMN medium,
    DROP COLUMN low,
    DROP COLUMN unknown;
