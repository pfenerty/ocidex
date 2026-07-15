-- name: GetSummaryCounts :one
WITH visible_sbom AS (
    SELECT s.id
    FROM sbom s
    LEFT JOIN registry r ON r.id = s.registry_id
    WHERE s.registry_id IS NULL
       OR r.visibility = 'public'
       OR r.owner_id = sqlc.narg('user_id')::uuid
       OR COALESCE(sqlc.narg('is_admin')::boolean, false)
)
SELECT
    (SELECT COUNT(*)::bigint FROM artifact a
       WHERE artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
    ) AS artifact_count,
    (SELECT COUNT(*)::bigint FROM visible_sbom) AS sbom_count,
    (SELECT COUNT(*)::bigint FROM (
        SELECT DISTINCT c.name, COALESCE(c.group_name,'') AS g, c.type
        FROM component c
        JOIN visible_sbom vs ON vs.id = c.sbom_id
    ) t) AS package_count,
    (SELECT COUNT(*)::bigint FROM (
        SELECT DISTINCT c.name, COALESCE(c.group_name,'') AS g, COALESCE(c.version,'') AS v, c.type
        FROM component c
        JOIN visible_sbom vs ON vs.id = c.sbom_id
    ) t) AS version_count,
    (SELECT COUNT(*)::bigint FROM license) AS license_count;

-- name: GetLicenseCategoryCounts :many
WITH visible_sbom AS (
    SELECT s.id
    FROM sbom s
    LEFT JOIN registry r ON r.id = s.registry_id
    WHERE s.registry_id IS NULL
       OR r.visibility = 'public'
       OR r.owner_id = sqlc.narg('user_id')::uuid
       OR COALESCE(sqlc.narg('is_admin')::boolean, false)
)
SELECT
    license_category(l.spdx_id) AS category,
    COUNT(DISTINCT cl.component_id)::bigint AS component_count
FROM license l
JOIN component_license cl ON cl.license_id = l.id
JOIN component c ON c.id = cl.component_id
JOIN visible_sbom vs ON vs.id = c.sbom_id
GROUP BY 1
ORDER BY component_count DESC;

-- name: GetSBOMIngestionTimeline :many
WITH visible_sbom AS (
    SELECT s.id, s.created_at
    FROM sbom s
    LEFT JOIN registry r ON r.id = s.registry_id
    WHERE s.registry_id IS NULL
       OR r.visibility = 'public'
       OR r.owner_id = sqlc.narg('user_id')::uuid
       OR COALESCE(sqlc.narg('is_admin')::boolean, false)
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
WITH visible_sbom AS (
    SELECT s.id, s.created_at
    FROM sbom s
    LEFT JOIN registry r ON r.id = s.registry_id
    WHERE s.registry_id IS NULL
       OR r.visibility = 'public'
       OR r.owner_id = sqlc.narg('user_id')::uuid
       OR COALESCE(sqlc.narg('is_admin')::boolean, false)
),
pkg_first_seen AS (
    SELECT DATE(MIN(vs.created_at)) AS first_seen
    FROM component c
    JOIN visible_sbom vs ON vs.id = c.sbom_id
    GROUP BY c.name, COALESCE(c.group_name, ''), c.type
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
-- Cumulative distinct package versions (name+group+version+type) by the day each first appeared.
WITH visible_sbom AS (
    SELECT s.id, s.created_at
    FROM sbom s
    LEFT JOIN registry r ON r.id = s.registry_id
    WHERE s.registry_id IS NULL
       OR r.visibility = 'public'
       OR r.owner_id = sqlc.narg('user_id')::uuid
       OR COALESCE(sqlc.narg('is_admin')::boolean, false)
),
ver_first_seen AS (
    SELECT DATE(MIN(vs.created_at)) AS first_seen
    FROM component c
    JOIN visible_sbom vs ON vs.id = c.sbom_id
    GROUP BY c.name, COALESCE(c.group_name, ''), COALESCE(c.version, ''), c.type
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
WITH visible_sbom AS (
    SELECT s.id
    FROM sbom s
    LEFT JOIN registry r ON r.id = s.registry_id
    WHERE s.registry_id IS NULL
       OR r.visibility = 'public'
       OR r.owner_id = sqlc.narg('user_id')::uuid
       OR COALESCE(sqlc.narg('is_admin')::boolean, false)
)
SELECT
    c.name,
    c.group_name,
    c.type,
    COUNT(DISTINCT COALESCE(c.version, ''))::bigint AS version_count,
    COUNT(DISTINCT c.sbom_id)::bigint               AS sbom_count
FROM component c
JOIN visible_sbom vs ON vs.id = c.sbom_id
GROUP BY c.name, c.group_name, c.type
ORDER BY version_count DESC
LIMIT @top_n::int;

-- name: GetVulnStats :one
-- Distinct tracked vulnerabilities reachable from any visible SBOM, with per-severity breakdown.
-- Deduplicates aliased OSV records (e.g. GO-xxxx + GHSA-yyyy) by canonical_id so each
-- real-world CVE is counted once.
WITH visible_sbom AS (
    SELECT s.id
    FROM sbom s
    LEFT JOIN registry r ON r.id = s.registry_id
    WHERE s.registry_id IS NULL
       OR r.visibility = 'public'
       OR r.owner_id = sqlc.narg('user_id')::uuid
       OR COALESCE(sqlc.narg('is_admin')::boolean, false)
)
SELECT
    COUNT(DISTINCT v.canonical_id)::bigint AS total_vulns,
    COUNT(DISTINCT v.canonical_id) FILTER (WHERE v.severity = 'CRITICAL')::bigint AS critical_count,
    COUNT(DISTINCT v.canonical_id) FILTER (WHERE v.severity = 'HIGH')::bigint     AS high_count,
    COUNT(DISTINCT v.canonical_id) FILTER (WHERE v.severity = 'MEDIUM')::bigint   AS medium_count,
    COUNT(DISTINCT v.canonical_id) FILTER (WHERE v.severity = 'LOW')::bigint      AS low_count,
    COUNT(DISTINCT v.canonical_id) FILTER (
        WHERE v.severity IS NULL OR v.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    )::bigint AS unknown_count
FROM component c
JOIN visible_sbom vs ON vs.id = c.sbom_id
JOIN package_vulnerability pv ON pv.purl = c.purl
JOIN vulnerability v ON v.id = pv.vulnerability_id
WHERE c.purl IS NOT NULL;
