-- name: UpsertArtifact :one
INSERT INTO artifact (type, name, group_name, purl, cpe)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (type, name, COALESCE(group_name, ''))
DO UPDATE SET
    purl = COALESCE(EXCLUDED.purl, artifact.purl),
    cpe  = COALESCE(EXCLUDED.cpe, artifact.cpe)
RETURNING id;

-- name: GetArtifact :one
SELECT id, type, name, group_name, purl, cpe, created_at
FROM artifact
WHERE id = $1;

-- name: ListArtifacts :many
SELECT a.id, a.type, a.name, a.group_name, a.purl, a.cpe, a.created_at,
       COUNT(s.id) AS sbom_count,
       COUNT(s.id) FILTER (WHERE s.enrichment_sufficient) AS sufficient_sbom_count,
       COUNT(*) OVER() AS total_count
FROM artifact a
LEFT JOIN sbom s ON s.artifact_id = a.id
WHERE (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('name')::text IS NULL OR a.name = sqlc.narg('name'))
  AND (sqlc.narg('require_sufficient')::boolean IS NULL
       OR NOT sqlc.narg('require_sufficient')::boolean
       OR EXISTS (SELECT 1 FROM sbom s2 WHERE s2.artifact_id = a.id AND s2.enrichment_sufficient))
GROUP BY a.id
ORDER BY a.name, a.type
LIMIT @row_limit OFFSET @row_offset;

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
       COUNT(*) OVER() AS total_count
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user' AND u.status = 'success'
WHERE s.artifact_id = $1
  AND (sqlc.narg('subject_version')::text IS NULL OR s.subject_version = sqlc.narg('subject_version'))
  AND (sqlc.narg('image_version')::text IS NULL
       OR COALESCE(e.data->>'imageVersion', u.data->>'imageVersion') = sqlc.narg('image_version'))
ORDER BY s.created_at DESC
LIMIT @row_limit OFFSET @row_offset;
