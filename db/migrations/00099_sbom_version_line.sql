-- +goose Up

-- Two more parts of subject_version, so "latest version" can be one definition
-- shared by every query instead of version parts with ingest time deciding the
-- rest.
--
-- version_prerelease: the suffix after the first '-' is a prerelease tag (rc,
-- pre, alpha, beta, dev, optionally numbered). Version parts alone rank
-- v1.21.0-pre.4 above the stable v1.20.5; a prerelease should headline only
-- when there is nothing else.
--
-- version_variant: that suffix when it is not a prerelease, so "trixie" in
-- 3.15.2-trixie. 3.15.2-trixie and 3.15.2-alpine are different images with the
-- same version parts, and ingest time is the wrong thing to choose between
-- them. A prerelease has no variant: v1.21.0-pre.4 is on the plain line.
--
-- The rule is shared with variantOf() in web/src/utils/versionDelta.ts and
-- service.VersionLine, and web/src/utils/versionLine.golden.json holds the cases
-- all three are tested against. Generated columns cannot read each other, so
-- the prerelease pattern appears twice.
DROP INDEX IF EXISTS idx_sbom_artifact_version;

ALTER TABLE sbom
    ADD COLUMN version_prerelease BOOLEAN NOT NULL
        GENERATED ALWAYS AS (COALESCE(subject_version ~* '^[^-]*-(rc|pre|alpha|beta|dev)(\.?\d+)?$', false)) STORED,
    ADD COLUMN version_variant TEXT NOT NULL
        GENERATED ALWAYS AS (
            CASE WHEN COALESCE(subject_version ~* '^[^-]*-(rc|pre|alpha|beta|dev)(\.?\d+)?$', false) THEN ''
                 ELSE COALESCE(substring(subject_version FROM '^[^-]*-(.*)$'), '')
            END) STORED;

-- Stable versions sort ahead of prereleases (false < true), then by version
-- parts as before.
CREATE INDEX idx_sbom_artifact_version ON sbom (
    artifact_id,
    version_prerelease,
    version_major DESC NULLS LAST,
    version_minor DESC NULLS LAST,
    version_patch DESC NULLS LAST,
    created_at DESC,
    id DESC
);

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_artifact_version;

ALTER TABLE sbom
    DROP COLUMN IF EXISTS version_variant,
    DROP COLUMN IF EXISTS version_prerelease;

CREATE INDEX idx_sbom_artifact_version ON sbom (
    artifact_id,
    version_major DESC NULLS LAST,
    version_minor DESC NULLS LAST,
    version_patch DESC NULLS LAST,
    created_at DESC,
    id DESC
);
