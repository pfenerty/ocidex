-- name: GetSummaryCounts :one
WITH visible_sbom AS (
    SELECT s.id
    FROM sbom s
    JOIN namespace n ON n.id = s.namespace_id
    WHERE n.id IN (SELECT visible_namespace_ids(
             sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
)
SELECT
    (SELECT COUNT(*)::bigint FROM artifact a
       WHERE artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
    ) AS artifact_count,
    (SELECT COUNT(*)::bigint FROM visible_sbom) AS sbom_count,
    -- Package and version counts come from component_rollup: it is already
    -- deduplicated to (namespace, identity) grain, so this reads 121k rows
    -- instead of 10.9M (ocidex-ckv.2). visible_namespace_ids() is exactly the
    -- visible_sbom predicate above, evaluated per namespace rather than per SBOM.
    --
    -- Packages are library identities only, the set /components lists. Counting
    -- every type took in syft's file entries, 117k of the 123k "packages" the
    -- home page reported against 6k on /components (ocidex-nps9.11; glossary in
    -- docs/ARCHITECTURE.md).
    (SELECT COUNT(*)::bigint FROM (
        SELECT DISTINCT r.name, COALESCE(r.group_name,'') AS g, r.type
        FROM component_rollup r
        WHERE r.type = 'library'
          AND (r.namespace_id IN (
                SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)))
    ) t) AS package_count,
    (SELECT COUNT(*)::bigint FROM (
        SELECT DISTINCT r.name, COALESCE(r.group_name,'') AS g, COALESCE(v.version,'') AS v, r.type
        FROM component_rollup r
        LEFT JOIN LATERAL unnest(r.versions) AS v(version) ON true
        WHERE r.type = 'library'
          AND (r.namespace_id IN (
                SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)))
    ) t) AS version_count,
    (SELECT COUNT(*)::bigint FROM license) AS license_count;

-- name: GetArtifactTypeCounts :many
-- Per-type breakdown of the same artifact set GetSummaryCounts counts as
-- artifact_count, so the two always sum consistently on the dashboard.
SELECT a.type, COUNT(*)::bigint AS artifact_count
FROM artifact a
WHERE artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
GROUP BY a.type
ORDER BY artifact_count DESC, a.type;

-- name: GetLicenseCategoryCounts :many
-- Reads license_rollup rather than joining component_license to component over
-- every visible SBOM: that was a full scan of the 10.9M-row table, run by the
-- stats warmer every five minutes per scope (ocidex-kf1p.5).
--
-- The count is distinct package identities (name, group, version, type) per
-- category, the same unit ListLicenses' component_count uses, where it was
-- distinct component rows. A package carried by a thousand SBOMs is one
-- package, so the breakdown now answers "how much of what we run is under
-- copyleft" rather than weighting each package by how often it was scanned.
SELECT
    license_category(l.spdx_id) AS category,
    COUNT(DISTINCT lr.identity_key)::bigint AS component_count
FROM license_rollup lr
JOIN license l ON l.id = lr.license_id
WHERE lr.namespace_id IN (SELECT visible_namespace_ids(
         sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
GROUP BY 1
ORDER BY component_count DESC;

-- name: GetSBOMIngestionTimeline :many
WITH visible_sbom AS (
    SELECT s.id, s.created_at
    FROM sbom s
    JOIN namespace n ON n.id = s.namespace_id
    WHERE n.id IN (SELECT visible_namespace_ids(
             sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
)
SELECT
    DATE(created_at)::text AS day,
    COUNT(*)::bigint       AS count
FROM visible_sbom
WHERE created_at >= CURRENT_DATE - @num_days::int
  AND DATE(created_at) <= CURRENT_DATE
GROUP BY DATE(created_at)::text
ORDER BY day;

-- name: GetPackageGrowthTimeline :many
-- Cumulative distinct packages (name+group+type) by the day each first appeared.
-- component_rollup carries each identity's first_seen per namespace, and the
-- earliest across the visible namespaces is the MIN of those, so this reads the
-- rollup instead of scanning component (ocidex-kf1p.5).
WITH pkg_first_seen AS (
    SELECT DATE(MIN(r.first_seen)) AS first_seen
    FROM component_rollup r
    WHERE r.namespace_id IN (SELECT visible_namespace_ids(
             sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    GROUP BY r.name, COALESCE(r.group_name, ''), r.type
),
daily_new AS (
    SELECT first_seen, COUNT(*)::bigint AS new_count
    FROM pkg_first_seen
    WHERE first_seen <= CURRENT_DATE
    GROUP BY first_seen
)
SELECT
    first_seen::text AS day,
    SUM(new_count) OVER (ORDER BY first_seen)::bigint AS cumulative_count
FROM daily_new
ORDER BY first_seen;

-- name: GetVersionGrowthTimeline :many
-- Cumulative distinct package versions (name+group+version+type) by the day each
-- first appeared. Reads component_version_rollup, the version-grain twin of the
-- package timeline's source (ocidex-kf1p.5).
WITH ver_first_seen AS (
    SELECT DATE(MIN(r.first_seen)) AS first_seen
    FROM component_version_rollup r
    WHERE r.namespace_id IN (SELECT visible_namespace_ids(
             sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    GROUP BY r.name, COALESCE(r.group_name, ''), COALESCE(r.version, ''), r.type
),
daily_new AS (
    SELECT first_seen, COUNT(*)::bigint AS new_count
    FROM ver_first_seen
    WHERE first_seen <= CURRENT_DATE
    GROUP BY first_seen
)
SELECT
    first_seen::text AS day,
    SUM(new_count) OVER (ORDER BY first_seen)::bigint AS cumulative_count
FROM daily_new
ORDER BY first_seen;

-- name: GetTopPackagesByVersionCount :many
-- Reads component_rollup (ocidex-ckv.2). The rollup is per-namespace, so the
-- version set is re-counted distinct across the visible rows while sbom_count
-- sums; the ordinality filter charges each rollup row once, since unnesting
-- versions multiplies the rows SUM would otherwise see.
SELECT
    r.name,
    r.group_name,
    r.type,
    COUNT(DISTINCT COALESCE(v.version, ''))::bigint AS version_count,
    COALESCE(SUM(r.sbom_count) FILTER (WHERE COALESCE(v.ord, 1) = 1), 0)::bigint AS sbom_count
FROM component_rollup r
LEFT JOIN LATERAL unnest(r.versions) WITH ORDINALITY AS v(version, ord) ON true
WHERE (r.namespace_id IN (
        SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)))
GROUP BY r.name, r.group_name, r.type
ORDER BY version_count DESC
LIMIT @top_n::int;

-- name: GetVulnStats :one
-- Distinct tracked vulnerabilities reachable from any visible SBOM, with
-- per-severity breakdown, one per canonical_id so aliased OSV records
-- (GO-xxxx + GHSA-yyyy) count once.
--
-- Reads vuln_rollup instead of joining component to package_vulnerability over
-- every visible SBOM, a full scan of component (ocidex-kf1p.5). Each canonical
-- vulnerability takes the severity ListTopVulnerabilities' canonical CTE picks
-- for it, so it lands in exactly one bucket and these totals agree with the
-- /vulnerabilities list rather than counting a record once per alias severity.
WITH canonical AS (
    SELECT DISTINCT ON (canonical_id) canonical_id, severity
    FROM vulnerability
    WHERE canonical_id != ''
    ORDER BY
        canonical_id,
        CASE WHEN severity IS NOT NULL AND severity NOT IN ('UNKNOWN') THEN 0 ELSE 1 END,
        modified_at DESC NULLS LAST
), reachable AS (
    SELECT DISTINCT vr.canonical_id
    FROM vuln_rollup vr
    WHERE vr.namespace_id IN (SELECT visible_namespace_ids(
             sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
)
SELECT
    COUNT(*)::bigint AS total_vulns,
    COUNT(*) FILTER (WHERE c.severity = 'CRITICAL')::bigint AS critical_count,
    COUNT(*) FILTER (WHERE c.severity = 'HIGH')::bigint     AS high_count,
    COUNT(*) FILTER (WHERE c.severity = 'MEDIUM')::bigint   AS medium_count,
    COUNT(*) FILTER (WHERE c.severity = 'LOW')::bigint      AS low_count,
    COUNT(*) FILTER (
        WHERE c.severity IS NULL OR c.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    )::bigint AS unknown_count
FROM reachable r
JOIN canonical c ON c.canonical_id = r.canonical_id;
