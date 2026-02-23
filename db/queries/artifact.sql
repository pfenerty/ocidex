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
       COUNT(*) OVER() AS total_count
FROM artifact a
LEFT JOIN sbom s ON s.artifact_id = a.id
WHERE (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('name')::text IS NULL OR a.name = sqlc.narg('name'))
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
       (e.data->>'created')::timestamptz AS build_date,
       e.data->>'imageVersion' AS image_version,
       e.data->>'architecture' AS architecture,
       COUNT(*) OVER() AS total_count
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
WHERE s.artifact_id = $1
  AND (sqlc.narg('subject_version')::text IS NULL OR s.subject_version = sqlc.narg('subject_version'))
ORDER BY s.created_at DESC
LIMIT @row_limit OFFSET @row_offset;
