-- +goose Up

-- 00071 derived sbom.version_major/minor/patch with an unbounded digit run:
--
--     NULLIF(substring(subject_version FROM '^v?(\d+)'), '')::int
--
-- subject_version is whatever tag the image carried, and a git-SHA tag that
-- happens to start with digits ("97595216784cd503cf34...") makes that capture
-- an 11-digit number. The ::int then raises 22003 and takes the whole INSERT
-- with it, so the SBOM can never be stored: the scan succeeds, ingest dies,
-- the row burns its retry budget and the next catalog walk re-queues it. On
-- ocidex.app this looped for 13 days across cilium/cilium-envoy and
-- kedacore/keda.
--
-- The parse is a best-effort ordering hint, not a constraint, so a value that
-- does not fit must read as "unknown" (NULL) exactly like 'main' or 'latest'
-- already does -- never as an error. Capping each run at 9 digits guarantees
-- the cast is in range (999999999 < 2147483647) and the trailing (?!\d) makes
-- a longer run fail to match rather than silently truncating to a wrong
-- number. A 10-digit major version is therefore NULL rather than an error;
-- nothing that is actually a version reaches ten digits.
DROP INDEX IF EXISTS idx_sbom_artifact_version;

ALTER TABLE sbom
    DROP COLUMN IF EXISTS version_major,
    DROP COLUMN IF EXISTS version_minor,
    DROP COLUMN IF EXISTS version_patch;

ALTER TABLE sbom
    ADD COLUMN version_major INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?(\d{1,9})(?!\d)'), '')::int) STORED,
    ADD COLUMN version_minor INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?\d{1,9}\.(\d{1,9})(?!\d)'), '')::int) STORED,
    ADD COLUMN version_patch INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?\d{1,9}\.\d{1,9}\.(\d{1,9})(?!\d)'), '')::int) STORED;

-- Recreated verbatim from 00071: dropping the columns dropped it with them.
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

ALTER TABLE sbom
    ADD COLUMN version_major INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?(\d+)'), '')::int) STORED,
    ADD COLUMN version_minor INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?\d+\.(\d+)'), '')::int) STORED,
    ADD COLUMN version_patch INT
        GENERATED ALWAYS AS (NULLIF(substring(subject_version FROM '^v?\d+\.\d+\.(\d+)'), '')::int) STORED;

CREATE INDEX idx_sbom_artifact_version ON sbom (
    artifact_id,
    version_major DESC NULLS LAST,
    version_minor DESC NULLS LAST,
    version_patch DESC NULLS LAST,
    created_at DESC,
    id DESC
);
