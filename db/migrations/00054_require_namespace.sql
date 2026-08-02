-- Close the NULL-visibility hole left open by 00053 (ocidex-0gp.3).
--
-- 00053 carried the `IS NULL` arm of the visibility rules forward unchanged
-- because rows with no owner still existed: every manually uploaded SBOM had
-- no registry, and treating "unowned" as "public" was the pre-ADR-039
-- behaviour. That arm is a read-visibility hole — anything ingested without a
-- source is world-readable.
--
-- Ingest now resolves a source (and through it a namespace) or fails with 400,
-- so nothing new can arrive unowned. This migration assigns the rows that
-- already did, then removes the arm and makes the column NOT NULL so the
-- database enforces what the service layer now promises.
--
-- Pre-existing unowned rows go to a private, unowned `unassigned` namespace:
-- private + owner_id NULL matches no viewer, so only an admin sees them. That
-- is deliberately fail-closed — these rows were world-readable by accident and
-- an admin can reassign them with PATCH /api/v1/namespaces/{id} once their real
-- owner is known. Deleting them instead would destroy data to fix a read rule.
--
-- sbom.namespace_id is already ON DELETE CASCADE, so NOT NULL introduces no
-- deletion conflict: dropping a namespace drops its SBOMs, which is the only
-- coherent outcome once an SBOM cannot exist unowned.

-- +goose Up

INSERT INTO namespace (name, owner_id, visibility)
SELECT 'unassigned', NULL, 'private'
WHERE EXISTS (SELECT 1 FROM sbom WHERE namespace_id IS NULL)
ON CONFLICT (name) DO NOTHING;

INSERT INTO source (namespace_id, kind, name)
SELECT n.id, 'upload', 'legacy'
FROM namespace n
WHERE n.name = 'unassigned'
ON CONFLICT (namespace_id, name) DO NOTHING;

UPDATE sbom s
SET namespace_id = src.namespace_id,
    source_id    = COALESCE(s.source_id, src.id)
FROM source src
JOIN namespace n ON n.id = src.namespace_id
WHERE n.name = 'unassigned' AND src.name = 'legacy'
  AND s.namespace_id IS NULL;

-- An artifact with no artifact_namespace row is the artifact_visible() twin of
-- the same hole. Link every artifact to the namespaces its SBOMs now live in;
-- an artifact with no SBOM at all stays unlinked and becomes admin-only, which
-- is the same fail-closed direction.
INSERT INTO artifact_namespace (artifact_id, namespace_id)
SELECT DISTINCT s.artifact_id, s.namespace_id
FROM sbom s
WHERE s.artifact_id IS NOT NULL
  AND NOT EXISTS (
        SELECT 1 FROM artifact_namespace an WHERE an.artifact_id = s.artifact_id
      )
ON CONFLICT DO NOTHING;

-- Rollups are derived from sbom.namespace_id, so their NULLs are the same rows.
-- Repoint them rather than forcing a full refresh: a refresh recomputes them
-- identically, but this keeps the migration self-contained.
UPDATE component_rollup r
SET namespace_id = n.id
FROM namespace n
WHERE n.name = 'unassigned' AND r.namespace_id IS NULL;

UPDATE license_rollup r
SET namespace_id = n.id
FROM namespace n
WHERE n.name = 'unassigned' AND r.namespace_id IS NULL;

UPDATE vuln_rollup r
SET namespace_id = n.id
FROM namespace n
WHERE n.name = 'unassigned' AND r.namespace_id IS NULL;

ALTER TABLE sbom ALTER COLUMN namespace_id SET NOT NULL;
ALTER TABLE component_rollup ALTER COLUMN namespace_id SET NOT NULL;
ALTER TABLE license_rollup ALTER COLUMN namespace_id SET NOT NULL;
ALTER TABLE vuln_rollup ALTER COLUMN namespace_id SET NOT NULL;

COMMENT ON COLUMN sbom.namespace_id IS
    'Who may see this SBOM. NOT NULL since 00054: ingest resolves a source, and through it a namespace, or fails (ADR-039, ocidex-0gp.3).';

-- Visibility functions without the unowned arm. Shape is otherwise identical:
-- sbom_visible() stays a per-row EXISTS and visible_namespace_ids() stays
-- set-returning, so 00052's semi-join plan is untouched. The rollup-query
-- contract 00053 recorded shortens accordingly — callers now write
-- `namespace_id IN (SELECT visible_namespace_ids(...))` with no IS NULL arm.
DROP FUNCTION IF EXISTS sbom_visible(UUID, UUID, BOOLEAN);
-- +goose StatementBegin
CREATE FUNCTION sbom_visible(ns_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR EXISTS (
           SELECT 1 FROM namespace
           WHERE id = ns_id
             AND (visibility = 'public' OR owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

DROP FUNCTION IF EXISTS artifact_visible(UUID, UUID, BOOLEAN);
-- +goose StatementBegin
CREATE FUNCTION artifact_visible(a_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR EXISTS (
           SELECT 1
           FROM artifact_namespace an
           JOIN namespace n ON n.id = an.namespace_id
           WHERE an.artifact_id = a_id
             AND (n.visibility = 'public' OR n.owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

-- +goose Down

-- Restores the permissive arms. The `unassigned` namespace and its rows are
-- left in place: the Up cannot record which rows were NULL before it ran, so
-- deleting them here would delete SBOMs an admin may since have reassigned.
-- Re-running the Up on a database that has already been down-migrated is a
-- no-op for those rows, which is correct.

DROP FUNCTION IF EXISTS artifact_visible(UUID, UUID, BOOLEAN);
-- +goose StatementBegin
CREATE FUNCTION artifact_visible(a_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR NOT EXISTS (SELECT 1 FROM artifact_namespace WHERE artifact_id = a_id)
      OR EXISTS (
           SELECT 1
           FROM artifact_namespace an
           JOIN namespace n ON n.id = an.namespace_id
           WHERE an.artifact_id = a_id
             AND (n.visibility = 'public' OR n.owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

DROP FUNCTION IF EXISTS sbom_visible(UUID, UUID, BOOLEAN);
-- +goose StatementBegin
CREATE FUNCTION sbom_visible(ns_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR ns_id IS NULL
      OR EXISTS (
           SELECT 1 FROM namespace
           WHERE id = ns_id
             AND (visibility = 'public' OR owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

ALTER TABLE vuln_rollup ALTER COLUMN namespace_id DROP NOT NULL;
ALTER TABLE license_rollup ALTER COLUMN namespace_id DROP NOT NULL;
ALTER TABLE component_rollup ALTER COLUMN namespace_id DROP NOT NULL;
ALTER TABLE sbom ALTER COLUMN namespace_id DROP NOT NULL;

COMMENT ON COLUMN sbom.namespace_id IS
    'Who may see this SBOM. Still nullable: legacy uploaded rows have no owner until ocidex-0gp.3 assigns one.';
