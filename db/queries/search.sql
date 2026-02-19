-- name: GetSBOM :one
SELECT id, serial_number, spec_version, version, artifact_id, subject_version, digest, created_at
FROM sbom
WHERE id = $1;

-- name: GetSBOMRaw :one
SELECT raw_bom
FROM sbom
WHERE id = $1;

-- name: ListSBOMs :many
SELECT id, serial_number, spec_version, version, artifact_id, subject_version, digest, created_at,
       COUNT(*) OVER() AS total_count
FROM sbom
WHERE (sqlc.narg('serial_number')::text IS NULL OR serial_number = sqlc.narg('serial_number'))
  AND (sqlc.narg('digest')::text IS NULL OR digest = sqlc.narg('digest'))
ORDER BY created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: ListSBOMsByDigest :many
SELECT id, serial_number, spec_version, version, artifact_id, subject_version, digest, created_at,
       COUNT(*) OVER() AS total_count
FROM sbom
WHERE digest = $1
ORDER BY created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: SearchComponents :many
SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
       COUNT(*) OVER() AS total_count
FROM component c
WHERE c.name = @name
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('version')::text IS NULL OR c.version = sqlc.narg('version'))
ORDER BY c.version_major DESC NULLS LAST,
         c.version_minor DESC NULLS LAST,
         c.version_patch DESC NULLS LAST
LIMIT @row_limit OFFSET @row_offset;

-- name: GetComponent :one
SELECT id, sbom_id, parent_id, bom_ref, type, name, group_name,
       version, purl, cpe, description, scope, publisher, copyright
FROM component
WHERE id = $1;

-- name: ListComponentHashes :many
SELECT algorithm, value
FROM component_hash
WHERE component_id = $1;

-- name: ListComponentLicenses :many
SELECT l.id, l.spdx_id, l.name, l.url
FROM license l
JOIN component_license cl ON cl.license_id = l.id
WHERE cl.component_id = $1;

-- name: ListComponentExtRefs :many
SELECT type, url, comment
FROM external_reference
WHERE component_id = $1;

-- name: ListLicenses :many
SELECT l.id, l.spdx_id, l.name, l.url,
       COUNT(DISTINCT cl.component_id) AS component_count,
       COUNT(*) OVER() AS total_count
FROM license l
LEFT JOIN component_license cl ON cl.license_id = l.id
WHERE (sqlc.narg('spdx_id')::text IS NULL OR l.spdx_id = sqlc.narg('spdx_id'))
  AND (sqlc.narg('name')::text IS NULL OR l.name ILIKE sqlc.narg('name'))
  AND (sqlc.narg('category')::text IS NULL OR
    CASE
      WHEN l.spdx_id IS NULL THEN 'uncategorized'
      WHEN l.spdx_id IN (
        'GPL-2.0','GPL-2.0-only','GPL-2.0-or-later',
        'GPL-3.0','GPL-3.0-only','GPL-3.0-or-later',
        'AGPL-3.0','AGPL-3.0-only','AGPL-3.0-or-later',
        'SSPL-1.0','EUPL-1.2'
      ) THEN 'copyleft'
      WHEN l.spdx_id IN (
        'LGPL-2.0','LGPL-2.0-only','LGPL-2.0-or-later',
        'LGPL-2.1','LGPL-2.1-only','LGPL-2.1-or-later',
        'LGPL-3.0','LGPL-3.0-only','LGPL-3.0-or-later',
        'MPL-2.0','EPL-1.0','EPL-2.0','CDDL-1.0','CDDL-1.1'
      ) THEN 'weak-copyleft'
      ELSE 'permissive'
    END = sqlc.narg('category')::text)
GROUP BY l.id, l.spdx_id, l.name, l.url
ORDER BY component_count DESC, l.name
LIMIT @row_limit OFFSET @row_offset;

-- name: ListComponentsByLicense :many
SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
       COUNT(*) OVER() AS total_count
FROM component c
JOIN component_license cl ON cl.component_id = c.id
WHERE cl.license_id = @license_id
ORDER BY c.name, c.version_major DESC NULLS LAST
LIMIT @row_limit OFFSET @row_offset;

-- name: LicenseSummaryByArtifact :many
SELECT l.id, l.spdx_id, l.name, l.url, COUNT(DISTINCT cl.component_id) AS component_count
FROM sbom s
JOIN component c ON c.sbom_id = s.id
JOIN component_license cl ON cl.component_id = c.id
JOIN license l ON l.id = cl.license_id
WHERE s.artifact_id = @artifact_id
  AND s.id = (
    SELECT id FROM sbom WHERE artifact_id = @artifact_id ORDER BY created_at DESC LIMIT 1
  )
GROUP BY l.id, l.spdx_id, l.name, l.url
ORDER BY component_count DESC, l.name;

-- name: ListDependenciesBySBOM :many
SELECT ref, depends_on
FROM dependency
WHERE sbom_id = $1
ORDER BY ref, depends_on;

-- name: CountSBOMComponents :one
SELECT COUNT(*) FROM component WHERE sbom_id = $1;

-- name: ListSBOMComponents :many
SELECT id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = $1
ORDER BY name, group_name;

-- name: ListComponentPurlTypes :many
SELECT DISTINCT split_part(replace(purl, 'pkg:', ''), '/', 1)::text AS purl_type
FROM component
WHERE purl IS NOT NULL
ORDER BY 1;

-- name: SearchDistinctComponents :many
SELECT c.name, c.group_name, c.type,
       COALESCE(string_agg(DISTINCT split_part(replace(c.purl, 'pkg:', ''), '/', 1), ',' ORDER BY split_part(replace(c.purl, 'pkg:', ''), '/', 1)) FILTER (WHERE c.purl IS NOT NULL), '') AS purl_types,
       COUNT(DISTINCT c.version) FILTER (WHERE c.version IS NOT NULL) AS version_count,
       COUNT(DISTINCT c.sbom_id) AS sbom_count,
       COUNT(*) OVER() AS total_count
FROM component c
WHERE (sqlc.narg('name')::text IS NULL OR c.name ILIKE sqlc.narg('name'))
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('type')::text IS NULL OR c.type = sqlc.narg('type'))
  AND (sqlc.narg('purl_type')::text IS NULL OR split_part(replace(c.purl, 'pkg:', ''), '/', 1) = sqlc.narg('purl_type'))
GROUP BY c.name, c.group_name, c.type
ORDER BY
  CASE @sort_by::text
    WHEN 'version_count' THEN COUNT(DISTINCT c.version) FILTER (WHERE c.version IS NOT NULL)
    WHEN 'sbom_count' THEN COUNT(DISTINCT c.sbom_id)
  END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
  c.name, c.group_name
LIMIT @row_limit OFFSET @row_offset;

-- name: GetComponentVersions :many
SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
       s.artifact_id, s.subject_version, s.digest AS sbom_digest,
       a.name AS artifact_name,
       s.created_at AS sbom_created_at
FROM component c
JOIN sbom s ON s.id = c.sbom_id
LEFT JOIN artifact a ON a.id = s.artifact_id
WHERE c.name = @name
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('version')::text IS NULL OR c.version = sqlc.narg('version'))
  AND (sqlc.narg('type')::text IS NULL OR c.type = sqlc.narg('type'))
ORDER BY c.version_major DESC NULLS LAST,
         c.version_minor DESC NULLS LAST,
         c.version_patch DESC NULLS LAST,
         s.created_at DESC;
