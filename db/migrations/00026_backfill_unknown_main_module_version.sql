-- +goose Up
-- Backfill component.version for existing rows where Syft emitted "UNKNOWN"
-- on the SBOM's main module. Mirrors the runtime rule in
-- service/main_module.go: when a component matches the SBOM's source
-- repository (extracted from raw_bom -> metadata -> properties or
-- raw_bom -> metadata -> component -> properties) AND its version is
-- "UNKNOWN" or empty, copy the SBOM's subject_version.
--
-- The match is exact path: the component's purl path or name must equal
-- the source URL stripped of scheme and ".git" suffix. Submodules are NOT
-- backfilled (their UNKNOWN may have unrelated causes).

WITH source_per_sbom AS (
    SELECT
        s.id AS sbom_id,
        s.subject_version,
        -- Try metadata.component.properties first, then top-level metadata.properties.
        COALESCE(
            (SELECT prop->>'value'
             FROM jsonb_array_elements(COALESCE(s.raw_bom #> '{metadata,component,properties}', '[]'::jsonb)) AS prop
             WHERE prop->>'name' IN (
                 'syft:image:labels:org.opencontainers.image.source',
                 'aquasecurity:trivy:Labels:org.opencontainers.image.source'
             )
             AND prop->>'value' <> ''
             LIMIT 1),
            (SELECT prop->>'value'
             FROM jsonb_array_elements(COALESCE(s.raw_bom #> '{metadata,properties}', '[]'::jsonb)) AS prop
             WHERE prop->>'name' IN (
                 'syft:image:labels:org.opencontainers.image.source',
                 'aquasecurity:trivy:Labels:org.opencontainers.image.source'
             )
             AND prop->>'value' <> ''
             LIMIT 1)
        ) AS raw_source
    FROM sbom s
    WHERE s.subject_version IS NOT NULL AND s.subject_version <> ''
),
main_module AS (
    SELECT
        sbom_id,
        subject_version,
        -- Strip scheme, user@ credentials, trailing .git, trailing /.
        regexp_replace(
            regexp_replace(
                regexp_replace(raw_source, '^[a-zA-Z+]+://', ''),
                '^[^/]*@',
                ''
            ),
            '(\.git)?/?$',
            ''
        ) AS module_path
    FROM source_per_sbom
    WHERE raw_source IS NOT NULL AND raw_source <> ''
)
UPDATE component c
SET version = mm.subject_version
FROM main_module mm
WHERE c.sbom_id = mm.sbom_id
  AND (c.version = 'UNKNOWN' OR c.version IS NULL OR c.version = '')
  AND mm.module_path <> ''
  AND (
      -- Match by purl path: pkg:<type>/<path>[@version][?qualifiers]
      regexp_replace(
          regexp_replace(c.purl, '^pkg:[^/]+/', ''),
          '[@?].*$',
          ''
      ) = mm.module_path
      -- Or match by name when purl is absent.
      OR (c.purl IS NULL AND c.name = mm.module_path)
  );

-- Recompute version_major/minor/patch for the rows we just touched. Use the
-- same parsing semantics as service.parseSemver: strip a leading 'v' if
-- present, then take the first three dot-separated integer segments.
UPDATE component c
SET
    version_major = NULLIF(substring(c.version FROM '^v?(\d+)'), '')::int,
    version_minor = NULLIF(substring(c.version FROM '^v?\d+\.(\d+)'), '')::int,
    version_patch = NULLIF(substring(c.version FROM '^v?\d+\.\d+\.(\d+)'), '')::int
FROM sbom s
WHERE c.sbom_id = s.id
  AND c.version = s.subject_version
  AND s.subject_version IS NOT NULL
  AND s.subject_version <> ''
  AND c.version IS NOT NULL
  AND c.version <> '';

-- +goose Down
-- Down: no inverse — we don't track which rows were backfilled. The forward
-- migration is idempotent (re-running it produces the same result), so a
-- down migration that resets to NULL would lose data added between Up and Down.
SELECT 1;
