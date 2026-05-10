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
--
-- Performance note: an earlier draft of this migration evaluated
-- regexp_replace on every component row and OOMed/hung on production-
-- size tables (~1M components). This version drives from the small
-- main_module CTE (~one row per SBOM with a source label, typically a
-- few hundred), uses the idx_component_sbom_id index to fetch per-SBOM
-- components, and matches by LIKE prefix instead of regex.

-- +goose StatementBegin
DO $$
DECLARE
    rec RECORD;
BEGIN
    -- Pre-build the (sbom_id, subject_version, module_path) tuples we care
    -- about. Tiny relative to component (one row per SBOM with a source label).
    CREATE TEMP TABLE _main_module ON COMMIT DROP AS
    WITH source_per_sbom AS (
        SELECT
            s.id AS sbom_id,
            s.subject_version,
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
    )
    SELECT
        sbom_id,
        subject_version,
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
    WHERE raw_source IS NOT NULL AND raw_source <> '';

    DELETE FROM _main_module WHERE module_path = '';

    -- For each main module, update at most a handful of matching components.
    -- Driving the loop here means every UPDATE statement touches only rows
    -- selected via idx_component_sbom_id — never a full sequential scan.
    --
    -- Filter on version IN ('UNKNOWN','') only — files legitimately have
    -- NULL version and we don't want to touch them. Restrict to library/
    -- application types for the same reason.
    FOR rec IN SELECT sbom_id, subject_version, module_path FROM _main_module LOOP
        UPDATE component c
        SET
            version       = rec.subject_version,
            version_major = NULLIF(substring(rec.subject_version FROM '^v?(\d+)'), '')::int,
            version_minor = NULLIF(substring(rec.subject_version FROM '^v?\d+\.(\d+)'), '')::int,
            version_patch = NULLIF(substring(rec.subject_version FROM '^v?\d+\.\d+\.(\d+)'), '')::int
        WHERE c.sbom_id = rec.sbom_id
          AND (c.version = 'UNKNOWN' OR c.version = '')
          AND c.type IN ('library', 'application')
          AND (
              -- purl form: 'pkg:<type>/<module_path>' optionally followed by @ or ?
              c.purl =      'pkg:golang/' || rec.module_path
              OR c.purl LIKE 'pkg:%/'      || rec.module_path
              OR c.purl LIKE 'pkg:%/'      || rec.module_path || '@%'
              OR c.purl LIKE 'pkg:%/'      || rec.module_path || '?%'
              -- Fallback: match by name when purl is absent.
              OR (c.purl IS NULL AND c.name = rec.module_path)
          );
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- No inverse: we don't track which rows were backfilled. The forward
-- migration is idempotent (re-running produces the same result).
SELECT 1;
