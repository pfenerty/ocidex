-- name: GetSBOMByDigest :one
SELECT id FROM sbom WHERE digest = $1;

-- name: GetSBOM :one
SELECT id, serial_number, spec_version, version, artifact_id, subject_version, digest, created_at, registry_id, index_digest
FROM sbom
WHERE id = $1;

-- name: GetSBOMRef :one
-- Lightweight SBOM lookup for building a SBOMRef: joins enrichments to get
-- architecture and build_date without fetching the raw BOM.
SELECT s.id, s.subject_version, s.created_at,
       COALESCE(e.data->>'architecture', u.data->>'architecture') AS architecture,
       COALESCE(
           (e.data->>'created')::timestamptz,
           (u.data->>'created')::timestamptz
       ) AS build_date
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user' AND u.status = 'success'
WHERE s.id = $1;

-- name: GetSBOMRaw :one
SELECT raw_bom
FROM sbom
WHERE id = $1;

-- name: IsSBOMVisible :one
SELECT sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean) AS visible
FROM sbom s WHERE s.id = $1;

-- name: IsArtifactVisible :one
SELECT artifact_visible($1, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean) AS visible;

-- name: ListSBOMs :many
-- Keyset pagination on (created_at DESC, id DESC); backed by idx_sbom_created_at_id.
-- The caller fetches row_limit+1 to detect whether a further page exists.
SELECT s.id, s.serial_number, s.spec_version, s.version, s.artifact_id, s.subject_version, s.digest, s.created_at
FROM sbom s
WHERE (sqlc.narg('serial_number')::text IS NULL OR s.serial_number = sqlc.narg('serial_number'))
  AND (sqlc.narg('digest')::text IS NULL OR s.digest = sqlc.narg('digest'))
  AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (s.created_at, s.id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY s.created_at DESC, s.id DESC
LIMIT @row_limit;

-- name: ListSBOMsByDigest :many
SELECT s.id, s.serial_number, s.spec_version, s.version, s.artifact_id, s.subject_version, s.digest, s.created_at,
       COUNT(*) OVER() AS total_count
FROM sbom s
WHERE s.digest = $1
  AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY s.created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: SearchComponents :many
SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
       COUNT(*) OVER() AS total_count
FROM component c
WHERE c.name = @name
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('version')::text IS NULL OR c.version = sqlc.narg('version'))
  AND EXISTS (
    SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
      AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  )
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
       COUNT(DISTINCT (c.name, COALESCE(c.group_name, ''), COALESCE(c.version, ''), c.type)) AS component_count,
       COUNT(*) OVER() AS total_count
FROM license l
LEFT JOIN component_license cl ON cl.license_id = l.id
LEFT JOIN component c ON c.id = cl.component_id
WHERE (sqlc.narg('spdx_id')::text IS NULL OR l.spdx_id = sqlc.narg('spdx_id'))
  AND (sqlc.narg('name')::text IS NULL OR l.name ILIKE sqlc.narg('name'))
  AND (sqlc.narg('category')::text IS NULL OR license_category(l.spdx_id) = sqlc.narg('category')::text)
  AND (c.id IS NULL OR EXISTS (
    SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
      AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  ))
GROUP BY l.id, l.spdx_id, l.name, l.url
ORDER BY component_count DESC, l.name
LIMIT @row_limit OFFSET @row_offset;

-- name: ListComponentsByLicense :many
WITH ranked AS (
    SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
           c.version_major, c.version_minor, c.version_patch,
           ROW_NUMBER() OVER (
               PARTITION BY c.name, COALESCE(c.group_name, ''), COALESCE(c.version, ''), c.type
               ORDER BY c.id
           ) AS rn
    FROM component c
    JOIN component_license cl ON cl.component_id = c.id
    WHERE cl.license_id = @license_id
      AND EXISTS (
        SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
          AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
      )
)
SELECT id, sbom_id, type, name, group_name, version, purl,
       COUNT(*) OVER() AS total_count
FROM ranked
WHERE rn = 1
ORDER BY name,
         version_major DESC NULLS LAST,
         version_minor DESC NULLS LAST,
         version_patch DESC NULLS LAST
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

-- name: GetSBOMMetadataBomRef :one
-- Returns metadata.component.bom-ref from the raw CycloneDX BOM, or NULL if absent.
SELECT raw_bom->'metadata'->'component'->>'bom-ref' AS bom_ref
FROM sbom
WHERE id = $1;

-- name: CountSBOMComponents :one
SELECT COUNT(*) FROM component WHERE sbom_id = $1;

-- name: CountSBOMPackages :one
-- Counts package components (excludes file entries), matching what the packages
-- tab displays.
SELECT COUNT(*) FROM component WHERE sbom_id = $1 AND type != 'file';

-- name: ListSBOMComponents :many
SELECT id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = $1
ORDER BY name, group_name;

-- name: ListSBOMComponentsPage :many
-- Keyset variant of ListSBOMComponents for the HTTP endpoint. Files are
-- excluded: the packages tab (the only consumer) shows packages only, and
-- including file components — which can vastly outnumber packages — would fill
-- whole pages with rows the client then filters out, leaving the list empty.
-- Ordered by (name, group_name, id) with NULL group_name folded to '' so the
-- cursor tuple comparison matches the ORDER BY. Access is gated by the service
-- before this runs. The caller fetches row_limit+1 to detect a further page.
SELECT id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = @sbom_id
  AND type != 'file'
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (name, COALESCE(group_name, ''), id) > (sqlc.narg('cursor_name')::text, sqlc.narg('cursor_group')::text, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY name, COALESCE(group_name, ''), id
LIMIT @row_limit;

-- name: ListSBOMPackages :many
SELECT id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = $1 AND type != 'file'
ORDER BY name, group_name;

-- name: ListSBOMPackagesBySBOMIDs :many
-- Batched variant of ListSBOMPackages: fetches packages for many SBOMs in one
-- round-trip (avoids the per-version N+1 in changelog generation). The caller
-- groups the rows by sbom_id.
SELECT sbom_id, id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = ANY(@sbom_ids::uuid[]) AND type != 'file'
ORDER BY sbom_id, name, group_name;

-- name: ListComponentPurlTypes :many
SELECT DISTINCT split_part(replace(purl, 'pkg:', ''), '/', 1)::text AS purl_type
FROM component
WHERE purl IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM sbom s WHERE s.id = component.sbom_id
      AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  )
ORDER BY 1
-- Safety cap: purl types are a small, fixed vocabulary; bound the scan.
LIMIT 200;

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
  AND EXISTS (
    SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
      AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  )
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
       s.created_at AS sbom_created_at,
       COALESCE(e.data->>'architecture', u.data->>'architecture') AS architecture
FROM component c
JOIN sbom s ON s.id = c.sbom_id
LEFT JOIN artifact a ON a.id = s.artifact_id
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user' AND u.status = 'success'
WHERE c.name = @name
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('version')::text IS NULL OR c.version = sqlc.narg('version'))
  AND (sqlc.narg('type')::text IS NULL OR c.type = sqlc.narg('type'))
  AND sbom_visible(s.registry_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY c.version_major DESC NULLS LAST,
         c.version_minor DESC NULLS LAST,
         c.version_patch DESC NULLS LAST,
         s.created_at DESC
-- Safety cap: bound a component's version history to the most recent rows.
LIMIT 200;
