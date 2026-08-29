-- Per-severity finding counts at SBOM grain (ocidex-unn8.7).
--
-- The Phase-2 severity columns (ocidex-unn8.8 on the artifact versions table,
-- .9 on /artifacts, .10 on /components) need a severity per SBOM on a list
-- page. Computing it live is not an option: ocidex-ckv.2 measured the same
-- shape of aggregation over the 10.9M-row component table at ~53s against a
-- 30s HTTP timeout, which is why 00051 exists at all. So this is a fourth
-- rollup alongside component_rollup / license_rollup / vuln_rollup.
--
-- Semantics are GetSBOMVulnSummary's, exactly: one finding per distinct
-- canonical_id (aliased OSV records — GO-… + GHSA-… for one CVE — count once),
-- and scope is purl ∪ source_purl per ocidex-unn8.2, so an advisory published
-- against a source package is not dropped. The severity buckets mirror
-- buildVulnSummary's switch, including its default arm: anything that is not
-- one of the four known labels, NULL included, lands in unknown.
--
-- Like every other rollup this one carries namespace_id and is grouped by it,
-- so a viewer's visible subset sums exactly at read time via
-- visible_namespace_ids().
--
-- CAVEAT for the consumers. A row exists only for an SBOM that has at least one
-- finding. A missing row therefore means *either* "no known vulnerabilities"
-- *or* "never scanned", and this table cannot tell them apart — the same gap
-- ADR-044 names for cluster workloads. A LEFT JOIN that renders a missing row
-- as a clean zero is the bug, not the fix; the caller has to consult scan state
-- to say "not scanned", exactly as the SBOM and artifact vulnerability tabs do.
--
-- The seeding INSERT below is the same query as sbomVulnRollupAggregate in
-- internal/repository/rollup_refresh.go and must be kept in step with it. That
-- rule is asserted by TestSBOMVulnRollupSeedMatchesTheRefreshAggregate, because
-- a divergence leaves the rollup correct immediately after migration and wrong
-- after the first refresh.

-- +goose Up

CREATE TABLE sbom_vuln_rollup (
    sbom_id      UUID   NOT NULL REFERENCES sbom (id) ON DELETE CASCADE,
    namespace_id UUID   REFERENCES namespace (id) ON DELETE CASCADE,
    critical     BIGINT NOT NULL DEFAULT 0,
    high         BIGINT NOT NULL DEFAULT 0,
    medium       BIGINT NOT NULL DEFAULT 0,
    low          BIGINT NOT NULL DEFAULT 0,
    unknown      BIGINT NOT NULL DEFAULT 0
);

-- One row per SBOM: namespace_id is functionally dependent on sbom_id, so the
-- aggregate's GROUP BY cannot produce two rows for one SBOM. Declaring that
-- unique lets the read side join without fanning out.
CREATE UNIQUE INDEX idx_sbom_vuln_rollup_sbom ON sbom_vuln_rollup (sbom_id);
CREATE INDEX idx_sbom_vuln_rollup_namespace ON sbom_vuln_rollup (namespace_id);

COMMENT ON TABLE sbom_vuln_rollup IS
    'Per-severity finding counts per SBOM, deduplicated by canonical_id, scoped purl ∪ source_purl. Absence of a row means no findings OR never scanned — callers must not render it as a clean zero.';

INSERT INTO sbom_vuln_rollup (sbom_id, namespace_id, critical, high, medium, low, unknown)
WITH scope AS (
    SELECT DISTINCT c1.sbom_id, c1.purl::text AS match_purl
    FROM component c1 WHERE c1.purl IS NOT NULL
    UNION
    SELECT DISTINCT c2.sbom_id, c2.source_purl::text AS match_purl
    FROM component c2 WHERE c2.source_purl IS NOT NULL
), findings AS (
    SELECT DISTINCT sc.sbom_id, v.canonical_id, v.severity
    FROM scope sc
    JOIN package_vulnerability pv ON pv.purl = sc.match_purl
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

-- +goose Down
DROP TABLE IF EXISTS sbom_vuln_rollup;
