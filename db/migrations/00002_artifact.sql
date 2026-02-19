-- +goose Up

-- artifact: deduplicated registry of software artifacts (subjects of SBOMs)
CREATE TABLE artifact (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type       TEXT NOT NULL,
    name       TEXT NOT NULL,
    group_name TEXT,
    purl       TEXT,
    cpe        TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_artifact_identity
    ON artifact (type, name, COALESCE(group_name, ''));

-- Link SBOMs to their subject artifact
ALTER TABLE sbom ADD COLUMN artifact_id UUID REFERENCES artifact(id);
ALTER TABLE sbom ADD COLUMN subject_version TEXT;

CREATE INDEX idx_sbom_artifact_id ON sbom (artifact_id) WHERE artifact_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_artifact_id;
ALTER TABLE sbom DROP COLUMN IF EXISTS subject_version;
ALTER TABLE sbom DROP COLUMN IF EXISTS artifact_id;
DROP TABLE IF EXISTS artifact;
