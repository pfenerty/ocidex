-- +goose Up

-- ListArtifacts picked an artifact's vulnerability counts from the SBOM with
-- the newest created_at — the most recently *ingested* one. That is not the
-- same thing as the latest version, and the difference is not cosmetic: a
-- re-scan or a backfill touching an old tag silently rewrote the artifact's
-- counts on the list page to that old tag's findings.
--
-- component has carried version_major/minor/patch since 00001 for exactly this
-- reason. sbom never got them, so there was no way to order its rows by version
-- at all. These three mirror that, using the same parse 00026 already applies
-- to component.
--
-- They are GENERATED ... STORED rather than plain columns with a backfill so
-- there is no second writer to keep in sync: every path that sets
-- subject_version — ingest, scanner, any future importer — gets correct parts
-- without knowing these columns exist, and no code can set them to something
-- that disagrees with the text they are derived from.
ALTER TABLE sbom
    ADD COLUMN version_major INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?(\d+)'), '')::int) STORED,
    ADD COLUMN version_minor INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?\d+\.(\d+)'), '')::int) STORED,
    ADD COLUMN version_patch INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?\d+\.\d+\.(\d+)'), '')::int) STORED;

-- Ordered to match ListArtifacts' lateral exactly, NULLS LAST included: a
-- subject_version that does not parse (a digest, a branch name) is unknown, not
-- newest, and DESC defaults to NULLS FIRST — so an index without the explicit
-- NULLS LAST could not serve the query.
CREATE INDEX idx_sbom_artifact_version ON sbom (
    artifact_id,
    version_major DESC NULLS LAST,
    version_minor DESC NULLS LAST,
    version_patch DESC NULLS LAST,
    created_at DESC,
    id DESC
);

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_artifact_version;
ALTER TABLE sbom
    DROP COLUMN IF EXISTS version_major,
    DROP COLUMN IF EXISTS version_minor,
    DROP COLUMN IF EXISTS version_patch;
