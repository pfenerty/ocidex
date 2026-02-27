-- name: GetSummaryCounts :one
SELECT
    (SELECT COUNT(*)::bigint FROM artifact)  AS artifact_count,
    (SELECT COUNT(*)::bigint FROM sbom)      AS sbom_count,
    (SELECT COUNT(*)::bigint FROM (SELECT DISTINCT name, COALESCE(group_name,'') AS g, type FROM component) t) AS package_count,
    (SELECT COUNT(*)::bigint FROM (SELECT DISTINCT name, COALESCE(group_name,'') AS g, COALESCE(version,'') AS v, type FROM component) t) AS version_count,
    (SELECT COUNT(*)::bigint FROM license)   AS license_count;

-- name: GetLicenseCategoryCounts :many
SELECT
    CASE
        WHEN l.spdx_id IS NOT NULL AND l.spdx_id ~* 'GPL|AGPL|EUPL|CDDL|OSL|CC-BY-SA' THEN 'copyleft'
        WHEN l.spdx_id IS NOT NULL AND l.spdx_id ~* 'LGPL|MPL|EPL|CPAL|APSL'          THEN 'weak-copyleft'
        WHEN l.spdx_id IS NOT NULL                                                      THEN 'permissive'
        ELSE 'uncategorized'
    END AS category,
    COUNT(DISTINCT cl.component_id)::bigint AS component_count
FROM license l
JOIN component_license cl ON cl.license_id = l.id
GROUP BY 1
ORDER BY component_count DESC;

-- name: GetSBOMIngestionTimeline :many
SELECT
    DATE(created_at)::text AS day,
    COUNT(*)::bigint       AS count
FROM sbom
WHERE created_at >= CURRENT_DATE - @num_days::int
  AND DATE(created_at) <= CURRENT_DATE
GROUP BY DATE(created_at)::text
ORDER BY day;

-- name: GetPackageGrowthTimeline :many
-- Cumulative distinct packages (name+group+type) by the day each first appeared.
WITH pkg_first_seen AS (
    SELECT DATE(MIN(s.created_at)) AS first_seen
    FROM component c
    JOIN sbom s ON s.id = c.sbom_id
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
WITH ver_first_seen AS (
    SELECT DATE(MIN(s.created_at)) AS first_seen
    FROM component c
    JOIN sbom s ON s.id = c.sbom_id
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
SELECT
    name,
    group_name,
    type,
    COUNT(DISTINCT COALESCE(version, ''))::bigint AS version_count,
    COUNT(DISTINCT sbom_id)::bigint               AS sbom_count
FROM component
GROUP BY name, group_name, type
ORDER BY version_count DESC
LIMIT @top_n::int;
