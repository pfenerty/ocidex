-- +goose Up

-- Junction table linking artifacts to the registries that discovered them.
-- An artifact can appear in multiple registries (overlapping registries).
CREATE TABLE artifact_registry (
    artifact_id UUID NOT NULL REFERENCES artifact(id) ON DELETE CASCADE,
    registry_id UUID NOT NULL REFERENCES registry(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (artifact_id, registry_id)
);

CREATE INDEX idx_artifact_registry_registry ON artifact_registry(registry_id);

-- Artifact-level visibility: visible if admin, no registry links (legacy), or
-- at least one linked registry is public or owned by the viewer.
CREATE FUNCTION artifact_visible(a_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR NOT EXISTS (SELECT 1 FROM artifact_registry WHERE artifact_id = a_id)
      OR EXISTS (
           SELECT 1
           FROM artifact_registry ar
           JOIN registry r ON r.id = ar.registry_id
           WHERE ar.artifact_id = a_id
             AND (r.visibility = 'public' OR r.owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;

-- Backfill from existing sbom.registry_id data.
INSERT INTO artifact_registry (artifact_id, registry_id)
SELECT DISTINCT s.artifact_id, s.registry_id
FROM sbom s
WHERE s.artifact_id IS NOT NULL
  AND s.registry_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- +goose Down
DROP FUNCTION IF EXISTS artifact_visible;
DROP TABLE IF EXISTS artifact_registry;
