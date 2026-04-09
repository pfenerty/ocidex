-- name: GetSummaryCounts :one
SELECT
    (SELECT COUNT(*)::bigint FROM artifact a
       WHERE artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
    ) AS artifact_count,
    (SELECT COUNT(*)::bigint FROM sbom s
       WHERE sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
    ) AS sbom_count,
    (SELECT COUNT(*)::bigint FROM (
        SELECT DISTINCT c.name, COALESCE(c.group_name,'') AS g, c.type
        FROM component c
        WHERE EXISTS (SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
            AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    ) t) AS package_count,
    (SELECT COUNT(*)::bigint FROM (
        SELECT DISTINCT c.name, COALESCE(c.group_name,'') AS g, COALESCE(c.version,'') AS v, c.type
        FROM component c
        WHERE EXISTS (SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
            AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    ) t) AS version_count,
    (SELECT COUNT(*)::bigint FROM license) AS license_count;

-- name: GetLicenseCategoryCounts :many
SELECT
    license_category(l.spdx_id) AS category,
    COUNT(DISTINCT cl.component_id)::bigint AS component_count
FROM license l
JOIN component_license cl ON cl.license_id = l.id
JOIN component c ON c.id = cl.component_id
WHERE EXISTS (SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
    AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
GROUP BY 1
ORDER BY component_count DESC;

-- name: GetSBOMIngestionTimeline :many
SELECT
    DATE(s.created_at)::text AS day,
    COUNT(*)::bigint         AS count
FROM sbom s
WHERE s.created_at >= CURRENT_DATE - @num_days::int
  AND DATE(s.created_at) <= CURRENT_DATE
  AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
GROUP BY DATE(s.created_at)::text
ORDER BY day;

-- name: GetPackageGrowthTimeline :many
-- Cumulative distinct packages (name+group+type) by the day each first appeared.
WITH pkg_first_seen AS (
    SELECT DATE(MIN(s.created_at)) AS first_seen
    FROM component c
    JOIN sbom s ON s.id = c.sbom_id
    WHERE sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
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
    WHERE sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
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
    c.name,
    c.group_name,
    c.type,
    COUNT(DISTINCT COALESCE(c.version, ''))::bigint AS version_count,
    COUNT(DISTINCT c.sbom_id)::bigint               AS sbom_count
FROM component c
WHERE EXISTS (SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
    AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
GROUP BY c.name, c.group_name, c.type
ORDER BY version_count DESC
LIMIT @top_n::int;
