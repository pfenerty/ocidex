-- name: UpsertArtifact :one
INSERT INTO artifact (type, name, group_name, purl, cpe)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (type, name, COALESCE(group_name, ''))
DO UPDATE SET
    purl = COALESCE(EXCLUDED.purl, artifact.purl),
    cpe  = COALESCE(EXCLUDED.cpe, artifact.cpe)
RETURNING id;

-- name: GetArtifact :one
SELECT a.id, a.type, a.name, a.group_name, a.purl, a.cpe, a.created_at,
       (SELECT CASE
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND (pe.data->>'verified')::boolean = true
           ) THEN 'verified'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND (pe.data->>'verified')::boolean = false
           ) THEN 'verification_failed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success'
                 AND ((pe.data->>'signaturePresent')::boolean = true
                      OR (pe.data->>'attestationPresent')::boolean = true)
           ) THEN 'signed'
           ELSE 'unsigned'
       END)::text AS signing_status
FROM artifact a
WHERE a.id = $1;

-- name: ListArtifacts :many
SELECT a.id, a.type, a.name, a.group_name, a.purl, a.cpe, a.created_at,
       COUNT(s.id) AS sbom_count,
       COUNT(s.id) FILTER (WHERE s.enrichment_sufficient) AS sufficient_sbom_count,
       (SELECT CASE
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND (pe.data->>'verified')::boolean = true
           ) THEN 'verified'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND (pe.data->>'verified')::boolean = false
           ) THEN 'verification_failed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success'
                 AND ((pe.data->>'signaturePresent')::boolean = true
                      OR (pe.data->>'attestationPresent')::boolean = true)
           ) THEN 'signed'
           ELSE 'unsigned'
       END)::text AS signing_status
FROM artifact a
LEFT JOIN sbom s ON s.artifact_id = a.id
WHERE (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('name')::text IS NULL OR a.name ILIKE '%' || sqlc.narg('name')::text || '%')
  AND (sqlc.narg('require_sufficient')::boolean IS NULL
       OR NOT sqlc.narg('require_sufficient')::boolean
       OR EXISTS (SELECT 1 FROM sbom s2 WHERE s2.artifact_id = a.id AND s2.enrichment_sufficient))
  AND artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (a.name, a.type, a.id) > (sqlc.narg('cursor_name')::text, sqlc.narg('cursor_type')::text, sqlc.narg('cursor_id')::uuid)
  )
GROUP BY a.id
ORDER BY a.name, a.type, a.id
LIMIT @row_limit;

-- name: CountSBOMsByArtifact :one
-- Counts visible SBOMs for an artifact. Replaces the prior trick of reading
-- COUNT(*) OVER() off ListSBOMsByArtifact, which is now keyset-paginated.
SELECT COUNT(*)
FROM sbom s
WHERE s.artifact_id = $1
  AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean);

-- name: GetArtifactOwnerID :one
SELECT r.owner_id
FROM artifact_registry ar
JOIN registry r ON r.id = ar.registry_id
WHERE ar.artifact_id = $1 AND r.owner_id IS NOT NULL
LIMIT 1;

-- name: UpsertArtifactRegistry :exec
INSERT INTO artifact_registry (artifact_id, registry_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteSBOMsByArtifact :execrows
DELETE FROM sbom WHERE artifact_id = $1;

-- name: DeleteArtifact :execrows
DELETE FROM artifact WHERE id = $1;

-- name: ListSBOMsByArtifact :many
SELECT s.id, s.serial_number, s.spec_version, s.version, s.subject_version, s.digest, s.created_at,
       (SELECT COUNT(*) FROM component c WHERE c.sbom_id = s.id) AS component_count,
       (COALESCE(e.data->>'created', u.data->>'created'))::timestamptz AS build_date,
       COALESCE(e.data->>'imageVersion', u.data->>'imageVersion') AS image_version,
       COALESCE(e.data->>'architecture', u.data->>'architecture') AS architecture,
       COALESCE(e.data->>'revision', u.data->>'revision') AS revision,
       COALESCE(e.data->>'sourceUrl', u.data->>'sourceUrl') AS source_url,
       s.enrichment_sufficient,
       s.flavor
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user' AND u.status = 'success'
WHERE s.artifact_id = $1
  AND (sqlc.narg('subject_version')::text IS NULL OR s.subject_version = sqlc.narg('subject_version'))
  AND (sqlc.narg('image_version')::text IS NULL
       OR COALESCE(e.data->>'imageVersion', u.data->>'imageVersion') = sqlc.narg('image_version'))
  AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (s.created_at, s.id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY s.created_at DESC, s.id DESC
LIMIT @row_limit;

-- name: ListArtifactVersions :many
WITH sboms_meta AS (
    SELECT
        s.id,
        s.created_at,
        s.enrichment_sufficient,
        COALESCE(s.subject_version,
            COALESCE(e.data->>'imageVersion', u.data->>'imageVersion'),
            s.id::text)                                                  AS version_key,
        COALESCE(e.data->>'architecture', u.data->>'architecture')       AS architecture,
        COALESCE(e.data->>'imageVersion',  u.data->>'imageVersion')      AS image_version,
        COALESCE(e.data->>'revision',      u.data->>'revision')          AS revision,
        COALESCE(e.data->>'sourceUrl',     u.data->>'sourceUrl')         AS source_url,
        (COALESCE(e.data->>'created',      u.data->>'created'))::timestamptz AS build_date,
        CASE
            WHEN (p.data->>'verified')::boolean = true THEN 'verified'
            WHEN (p.data->>'verified')::boolean = false THEN 'verification_failed'
            WHEN (p.data->>'signaturePresent')::boolean = true
                 OR (p.data->>'attestationPresent')::boolean = true THEN 'signed'
            ELSE 'unsigned'
        END AS signing_status
    FROM sbom s
    LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
    LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user'         AND u.status = 'success'
    LEFT JOIN enrichment p ON p.sbom_id = s.id AND p.enricher_name = 'provenance'   AND p.status = 'success'
    WHERE s.artifact_id = $1
      AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
),
newest_per_version AS (
    SELECT DISTINCT ON (version_key)
        id, version_key, created_at, enrichment_sufficient, image_version, revision, source_url, build_date, signing_status
    FROM sboms_meta
    ORDER BY version_key, created_at DESC
),
architectures_per_version AS (
    SELECT
        version_key,
        array_agg(DISTINCT architecture) FILTER (WHERE architecture IS NOT NULL) AS architectures
    FROM sboms_meta
    GROUP BY version_key
),
sbom_count_per_version AS (
    SELECT version_key, COUNT(*) AS sbom_count
    FROM sboms_meta
    GROUP BY version_key
)
SELECT
    n.version_key,
    n.id           AS newest_sbom_id,
    n.created_at,
    n.enrichment_sufficient,
    n.image_version,
    n.revision,
    n.source_url,
    n.build_date,
    n.signing_status,
    a.architectures,
    c.sbom_count,
    COUNT(*) OVER() AS total_count
FROM newest_per_version n
JOIN architectures_per_version a ON a.version_key = n.version_key
JOIN sbom_count_per_version c ON c.version_key = n.version_key
ORDER BY n.created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: CountArtifactVersions :one
SELECT COUNT(DISTINCT
    COALESCE(s.subject_version,
        COALESCE(e.data->>'imageVersion', u.data->>'imageVersion'),
        s.id::text)
)::bigint AS version_count
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user'         AND u.status = 'success'
WHERE s.artifact_id = $1
  AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean);
