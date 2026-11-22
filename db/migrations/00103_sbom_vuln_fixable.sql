-- +goose Up

-- How many of an SBOM's findings have a fix. Most of a large image's findings
-- are often packages the distro will not fix or has not yet (linux-libc-dev
-- alone was 516 of golang's 853), and a headline that counts them alike says
-- nothing about what can be done. fixable is the findings some matching
-- package record gives a fixed version for; the rest have none available.
--
-- Appended last, where the refresh pass's positional INSERT ... SELECT * puts
-- it, and re-seeded so the table is right before the first pass. The seed is
-- the refresh aggregate (sbomVulnRollupAggregate), verbatim.
ALTER TABLE sbom_vuln_rollup ADD COLUMN fixable BIGINT NOT NULL DEFAULT 0;

TRUNCATE sbom_vuln_rollup;
INSERT INTO sbom_vuln_rollup (sbom_id, namespace_id, critical, high, medium, low, unknown, fixable)
WITH scope AS (
    SELECT DISTINCT c1.sbom_id, c1.purl::text AS match_purl, COALESCE(c1.go_symbol_set_id, 0) AS go_symbol_set_id
    FROM component c1 WHERE c1.purl IS NOT NULL
    UNION
    SELECT DISTINCT c2.sbom_id, c2.source_purl::text AS match_purl, 0::bigint AS go_symbol_set_id
    FROM component c2 WHERE c2.source_purl IS NOT NULL
), findings AS (
    SELECT sc.sbom_id, v.canonical_id, v.severity,
           bool_or(COALESCE(pv.fixed_version, '') <> '') AS fixed
    FROM scope sc
    JOIN package_vulnerability pv ON pv.purl = sc.match_purl AND pv.go_symbol_set_id = sc.go_symbol_set_id
    JOIN vulnerability v ON v.id = pv.vulnerability_id
    GROUP BY sc.sbom_id, v.canonical_id, v.severity
)
SELECT f.sbom_id, s.namespace_id,
       count(*) FILTER (WHERE f.severity = 'CRITICAL')::bigint AS critical,
       count(*) FILTER (WHERE f.severity = 'HIGH')::bigint     AS high,
       count(*) FILTER (WHERE f.severity = 'MEDIUM')::bigint   AS medium,
       count(*) FILTER (WHERE f.severity = 'LOW')::bigint      AS low,
       count(*) FILTER (WHERE f.severity IS NULL
                           OR f.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))::bigint AS unknown,
       count(*) FILTER (WHERE f.fixed)::bigint AS fixable
FROM findings f
JOIN sbom s ON s.id = f.sbom_id
GROUP BY f.sbom_id, s.namespace_id;

-- +goose Down
ALTER TABLE sbom_vuln_rollup DROP COLUMN IF EXISTS fixable;

TRUNCATE sbom_vuln_rollup;
INSERT INTO sbom_vuln_rollup (sbom_id, namespace_id, critical, high, medium, low, unknown)
WITH scope AS (
    SELECT DISTINCT c1.sbom_id, c1.purl::text AS match_purl, COALESCE(c1.go_symbol_set_id, 0) AS go_symbol_set_id
    FROM component c1 WHERE c1.purl IS NOT NULL
    UNION
    SELECT DISTINCT c2.sbom_id, c2.source_purl::text AS match_purl, 0::bigint AS go_symbol_set_id
    FROM component c2 WHERE c2.source_purl IS NOT NULL
), findings AS (
    SELECT DISTINCT sc.sbom_id, v.canonical_id, v.severity
    FROM scope sc
    JOIN package_vulnerability pv ON pv.purl = sc.match_purl AND pv.go_symbol_set_id = sc.go_symbol_set_id
    JOIN vulnerability v ON v.id = pv.vulnerability_id
)
SELECT f.sbom_id, s.namespace_id,
       count(*) FILTER (WHERE f.severity = 'CRITICAL')::bigint AS critical,
       count(*) FILTER (WHERE f.severity = 'HIGH')::bigint     AS high,
       count(*) FILTER (WHERE f.severity = 'MEDIUM')::bigint   AS medium,
       count(*) FILTER (WHERE f.severity = 'LOW')::bigint      AS low,
       count(*) FILTER (WHERE f.severity IS NULL
                           OR f.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))::bigint AS unknown
FROM findings f
JOIN sbom s ON s.id = f.sbom_id
GROUP BY f.sbom_id, s.namespace_id;
