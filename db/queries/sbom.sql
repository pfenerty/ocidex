-- name: InsertSBOM :one
INSERT INTO sbom (serial_number, spec_version, version, raw_bom, artifact_id, subject_version, digest, namespace_id, source_id, flavor, index_digest)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, serial_number, spec_version, version, created_at;

-- name: UpdateSBOMFlavor :exec
UPDATE sbom SET flavor = $2 WHERE id = $1;

-- name: InsertComponent :one
INSERT INTO component (
    sbom_id, parent_id, bom_ref, type, name, group_name,
    version, version_major, version_minor, version_patch,
    purl, cpe, description, scope, publisher, copyright,
    layer_id, found_by, source_package, source_version, source_purl
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13, $14, $15, $16,
    $17, $18, $19, $20, $21
)
RETURNING id;

-- name: InsertComponentHash :exec
INSERT INTO component_hash (component_id, algorithm, value)
VALUES ($1, $2, $3);

-- name: UpsertLicenseBySPDX :one
INSERT INTO license (spdx_id, name, url)
VALUES ($1, $2, $3)
ON CONFLICT (spdx_id) WHERE spdx_id IS NOT NULL
DO UPDATE SET name = EXCLUDED.name
RETURNING id;

-- name: UpsertLicenseByName :one
INSERT INTO license (name, url)
VALUES ($1, $2)
ON CONFLICT (name) WHERE spdx_id IS NULL
DO UPDATE SET url = COALESCE(EXCLUDED.url, license.url)
RETURNING id;

-- name: InsertComponentLicense :exec
INSERT INTO component_license (component_id, license_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: InsertDependency :exec
INSERT INTO dependency (sbom_id, ref, depends_on)
VALUES ($1, $2, $3);

-- name: InsertExternalReference :exec
INSERT INTO external_reference (component_id, type, url, comment)
VALUES ($1, $2, $3, $4);

-- name: ListSBOMsWithoutFlavor :many
SELECT id, subject_version, raw_bom
FROM sbom
WHERE flavor IS NULL OR flavor = '';

-- name: ListSBOMsWithMissingProvenance :many
-- file_path alone selects the work, rather than the conjunction of every
-- provenance column that stood here before 00072. A row backfilled by an
-- earlier run has layer_id set and file_path NULL, so the old predicate would
-- have skipped it forever and ADR-048's rule would never reach the corpus it
-- exists for. A component whose SBOM records no location is re-selected on
-- every run and written unchanged — the same waste the old conjunction already
-- carried for components with no source package.
SELECT DISTINCT s.id, s.flavor, s.raw_bom
FROM sbom s
JOIN component c ON c.sbom_id = s.id
WHERE c.bom_ref IS NOT NULL AND c.bom_ref != ''
  AND c.file_path IS NULL;

-- name: ListSBOMComponentsMissingProvenance :many
SELECT id, bom_ref, purl FROM component
WHERE sbom_id = $1
  AND bom_ref IS NOT NULL AND bom_ref != ''
  AND file_path IS NULL;

-- name: UpdateComponentProvenance :exec
UPDATE component
SET layer_id = $2, found_by = $3, source_package = $4, source_version = $5, source_purl = $6,
    file_path = $7
WHERE id = $1;

-- name: DeleteSBOM :execrows
DELETE FROM sbom WHERE id = $1;

-- name: ListDigestsBySource :many
-- Digests already ingested through one channel, so a rescan can skip them. Keyed
-- on source rather than namespace: two sources in one namespace are scanned
-- independently.
SELECT DISTINCT digest FROM sbom
WHERE source_id = $1 AND digest IS NOT NULL;

-- name: LookupSBOMs :many
-- ADR-042 R3/R4: name-keyed resolver with two query forms sharing one plan.
--
-- Ladder form: artifact + version -> +arch -> +flavor. `version` is matched
-- against the same COALESCE expression ListArtifactVersions derives version_key
-- from, so a version copied out of the versions view resolves here; the
-- s.id::text fallback is deliberately omitted, since a UUID-shaped version is
-- not a name anyone composes.
--
-- Digest form: `digest` alone. idx_sbom_digest is UNIQUE, so that form matches
-- at most one row and can never produce a 409.
--
-- artifact is LEFT JOINed because sbom.artifact_id is nullable — a digest
-- lookup must still find an SBOM that was never linked to an artifact.
--
-- R5: sbom_visible() is applied here so the caller counts only visible
-- candidates.
SELECT s.id,
       a.name AS artifact_name,
       COALESCE(s.subject_version,
           COALESCE(e.data->>'imageVersion', u.data->>'imageVersion'))   AS version_key,
       -- The empty-string fallback is load-bearing, not cosmetic: the cast is what
    -- lets sqlc type this column at all, and a cast expression is inferred NOT
    -- NULL, so a row with neither enrichment -- an SBOM that arrived by upload,
    -- or one the oci-metadata enricher has not reached yet -- would fail to scan
    -- and 500 the whole lookup (ocidex-klj4). Absent architecture reads as "",
    -- which is how every other qualifier here already spells absent.
    COALESCE(e.data->>'architecture', u.data->>'architecture', '')::text AS architecture,
       s.flavor,
       s.digest
FROM sbom s
LEFT JOIN artifact a ON a.id = s.artifact_id
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user'         AND u.status = 'success'
WHERE (sqlc.narg('digest')::text IS NULL OR s.digest = sqlc.narg('digest'))
  AND (sqlc.narg('artifact')::text IS NULL OR a.name = sqlc.narg('artifact'))
  AND (sqlc.narg('version')::text IS NULL
       OR COALESCE(s.subject_version,
              COALESCE(e.data->>'imageVersion', u.data->>'imageVersion')) = sqlc.narg('version'))
  AND (sqlc.narg('arch')::text IS NULL
       OR COALESCE(e.data->>'architecture', u.data->>'architecture') = sqlc.narg('arch'))
  AND (sqlc.narg('flavor')::text IS NULL OR s.flavor = sqlc.narg('flavor'))
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY s.created_at DESC, s.id DESC
LIMIT 50;

-- name: UpdateSBOMSubjectVersion :exec
UPDATE sbom SET subject_version = $2 WHERE id = $1;
