-- name: InsertSBOM :one
INSERT INTO sbom (serial_number, spec_version, version, raw_bom, artifact_id, subject_version, digest, registry_id, flavor, index_digest)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
SELECT DISTINCT s.id, s.flavor, s.raw_bom
FROM sbom s
JOIN component c ON c.sbom_id = s.id
WHERE c.bom_ref IS NOT NULL AND c.bom_ref != ''
  AND c.layer_id IS NULL AND c.found_by IS NULL
  AND c.source_package IS NULL AND c.source_version IS NULL AND c.source_purl IS NULL;

-- name: ListSBOMComponentsMissingProvenance :many
SELECT id, bom_ref, purl FROM component
WHERE sbom_id = $1
  AND bom_ref IS NOT NULL AND bom_ref != ''
  AND layer_id IS NULL AND found_by IS NULL
  AND source_package IS NULL AND source_version IS NULL AND source_purl IS NULL;

-- name: UpdateComponentProvenance :exec
UPDATE component
SET layer_id = $2, found_by = $3, source_package = $4, source_version = $5, source_purl = $6
WHERE id = $1;

-- name: DeleteSBOM :execrows
DELETE FROM sbom WHERE id = $1;

-- name: ListDigestsByRegistry :many
SELECT DISTINCT digest FROM sbom
WHERE registry_id = $1 AND digest IS NOT NULL;

-- name: UpdateSBOMSubjectVersion :exec
UPDATE sbom SET subject_version = $2 WHERE id = $1;
