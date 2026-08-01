-- Splits `registry` into three tables along the lines set out in ADR-039
-- (ocidex-9xs.2).
--
-- `registry` was doing four jobs at once: ownership/visibility, channel
-- identity, discovery config, and trust policy. Only the first has anything to
-- do with authorization, and it is the only one an uploaded SBOM needs — so
-- fusing it to the other three is what makes non-container artifacts
-- impossible to own.
--
--   namespace  ownership + visibility        the authorization anchor
--   source     the ingest channel            'oci_registry' | 'upload'
--   registry   OCI discovery + trust         subtype, keyed on source.id
--
-- The rename is cheap because ids are preserved. Each existing registry yields
-- one namespace AND one source that both reuse registry.id, so every stored
-- registry_id value remains correct as both namespace_id and source_id. This
-- is repointed foreign keys, not a data remap — no UPDATE touches a data row.
--
-- scan_jobs deliberately keeps keying on registry_id: only OCI sources get
-- scanned. If that column had wanted to move too, the subtype line would be
-- drawn in the wrong place; it staying put is the check that it isn't.
--
-- Two behaviour changes fall out of the new foreign keys, both improvements:
--
--   1. Deleting a registry no longer leaks its SBOMs. Today
--      sbom.registry_id is ON DELETE SET NULL and sbom_visible() treats a NULL
--      registry as visible to everyone, so DELETE FROM registry silently makes
--      every SBOM of a *private* registry world-readable. Now the namespace
--      survives the registry, so deletion clears only channel attribution
--      (sbom.source_id) and visibility is unchanged.
--   2. Deletion moves up to the source. registry.id references source(id) ON
--      DELETE CASCADE, so removing a source removes its registry. Deleting the
--      registry row alone would strand its source; the service layer deletes
--      sources, not registries (ocidex-9xs.4).
--
-- What this migration does NOT do: make namespace_id NOT NULL. Rows with a NULL
-- registry_id exist today (every manually uploaded SBOM) and the IS NULL arm of
-- the visibility functions is carried forward unchanged for now. Assigning
-- those rows an owner and dropping that arm needs the upload/source binding
-- from ocidex-0gp.3, and is done there. One risky change at a time.

-- +goose Up

-- +goose StatementBegin
CREATE TABLE namespace (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL UNIQUE,
    owner_id   UUID        REFERENCES ocidex_user (id) ON DELETE SET NULL,
    visibility TEXT        NOT NULL DEFAULT 'private'
                           CHECK (visibility IN ('public', 'private')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

COMMENT ON TABLE namespace IS
    'Tenancy boundary. The only table carrying ownership and visibility (ADR-039). A namespace may hold several sources.';
COMMENT ON COLUMN namespace.visibility IS
    'Defaults to private. Namespaces migrated from registries keep the registry''s existing value, so this default only applies to namespaces created after the migration.';

-- +goose StatementBegin
CREATE TABLE source (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace_id UUID        NOT NULL REFERENCES namespace (id) ON DELETE CASCADE,
    kind         TEXT        NOT NULL CHECK (kind IN ('oci_registry', 'upload')),
    name         TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (namespace_id, name)
);
-- +goose StatementEnd

COMMENT ON TABLE source IS
    'How an SBOM reached OCIDex. kind is the subtype discriminator; an oci_registry source has a matching registry row, an upload source has none.';
COMMENT ON COLUMN source.kind IS
    'Not to be confused with registry.type (zot/harbor/docker/generic), which is an OCI-flavour hint for the scanner and is meaningless for an upload.';

CREATE INDEX idx_source_namespace_id ON source (namespace_id);
CREATE INDEX idx_namespace_owner_id ON namespace (owner_id) WHERE owner_id IS NOT NULL;

-- One namespace and one source per existing registry, both reusing registry.id.
INSERT INTO namespace (id, name, owner_id, visibility, created_at, updated_at)
SELECT id, name, owner_id, visibility, created_at, updated_at FROM registry;

INSERT INTO source (id, namespace_id, kind, name, created_at, updated_at)
SELECT id, id, 'oci_registry', name, created_at, updated_at FROM registry;

-- registry becomes the oci_registry subtype. Its identity and ownership columns
-- now live upstream; url, auth, patterns and trust config stay.
ALTER TABLE registry ADD CONSTRAINT registry_id_fkey
    FOREIGN KEY (id) REFERENCES source (id) ON DELETE CASCADE;
DROP INDEX IF EXISTS idx_registry_owner_id;
ALTER TABLE registry DROP COLUMN name;
ALTER TABLE registry DROP COLUMN owner_id;
ALTER TABLE registry DROP COLUMN visibility;

COMMENT ON TABLE registry IS
    'OCI-specific discovery and trust config. Subtype of source: registry.id IS the source id. Ownership lives on namespace (ADR-039).';

-- sbom: registry_id becomes namespace_id (who may see it), plus a new source_id
-- (how it arrived). Both backfill from the same value.
ALTER TABLE sbom DROP CONSTRAINT IF EXISTS sbom_registry_id_fkey;
ALTER TABLE sbom RENAME COLUMN registry_id TO namespace_id;
ALTER INDEX IF EXISTS idx_sbom_registry_id RENAME TO idx_sbom_namespace_id;
ALTER TABLE sbom ADD CONSTRAINT sbom_namespace_id_fkey
    FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON DELETE CASCADE;

ALTER TABLE sbom ADD COLUMN source_id UUID REFERENCES source (id) ON DELETE SET NULL;
UPDATE sbom SET source_id = namespace_id WHERE namespace_id IS NOT NULL;
CREATE INDEX idx_sbom_source_id ON sbom (source_id);

COMMENT ON COLUMN sbom.namespace_id IS
    'Who may see this SBOM. Still nullable: legacy uploaded rows have no owner until ocidex-0gp.3 assigns one.';
COMMENT ON COLUMN sbom.source_id IS
    'How this SBOM arrived. ON DELETE SET NULL: removing a channel loses attribution, never the SBOM and never its visibility.';

-- artifact_registry was never about registries either — same visibility-bucket
-- role as the rollups.
ALTER TABLE artifact_registry DROP CONSTRAINT IF EXISTS artifact_registry_registry_id_fkey;
ALTER TABLE artifact_registry RENAME COLUMN registry_id TO namespace_id;
ALTER TABLE artifact_registry RENAME TO artifact_namespace;
ALTER INDEX IF EXISTS idx_artifact_registry_registry RENAME TO idx_artifact_namespace_namespace;
ALTER TABLE artifact_namespace ADD CONSTRAINT artifact_namespace_namespace_id_fkey
    FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON DELETE CASCADE;
-- Cosmetic: the artifact FK kept the table's old name. RENAME CONSTRAINT has no
-- IF EXISTS, so both directions are guarded rather than assuming which name is
-- present.
-- +goose StatementBegin
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint
             WHERE conname = 'artifact_registry_artifact_id_fkey'
               AND conrelid = 'artifact_namespace'::regclass) THEN
    ALTER TABLE artifact_namespace RENAME CONSTRAINT artifact_registry_artifact_id_fkey
        TO artifact_namespace_artifact_id_fkey;
  END IF;
END $$;
-- +goose StatementEnd

-- Rollups. 00051's own comment describes registry_id as the thing sbom_visible
-- is "a function of" — i.e. a visibility bucket. Renaming it makes the column
-- say what the queries already mean. The stored values are unchanged, and
-- "an SBOM belongs to exactly one namespace" preserves 00051's sum-without-
-- double-counting property verbatim.
ALTER TABLE component_rollup DROP CONSTRAINT IF EXISTS component_rollup_registry_id_fkey;
ALTER TABLE component_rollup RENAME COLUMN registry_id TO namespace_id;
ALTER TABLE component_rollup ADD CONSTRAINT component_rollup_namespace_id_fkey
    FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON DELETE CASCADE;

ALTER TABLE license_rollup DROP CONSTRAINT IF EXISTS license_rollup_registry_id_fkey;
ALTER TABLE license_rollup RENAME COLUMN registry_id TO namespace_id;
ALTER TABLE license_rollup ADD CONSTRAINT license_rollup_namespace_id_fkey
    FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON DELETE CASCADE;

ALTER TABLE vuln_rollup DROP CONSTRAINT IF EXISTS vuln_rollup_registry_id_fkey;
ALTER TABLE vuln_rollup RENAME COLUMN registry_id TO namespace_id;
ALTER TABLE vuln_rollup ADD CONSTRAINT vuln_rollup_namespace_id_fkey
    FOREIGN KEY (namespace_id) REFERENCES namespace (id) ON DELETE CASCADE;

-- Visibility functions, repointed at namespace. The three disjuncts are
-- unchanged in meaning; only the table they read from moves.
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

-- Set-returning form, for the rollup read paths. Keeps 00052's exact shape:
-- the planner evaluates the rule once per namespace and semi-joins, instead of
-- once per rollup row. Losing that shape reintroduces the 3,818 ms scan node
-- 00052 was written to remove, so callers must keep using
-- `namespace_id IS NULL OR namespace_id IN (SELECT ...)`.
DROP FUNCTION IF EXISTS visible_registry_ids(UUID, BOOLEAN);
-- +goose StatementBegin
CREATE FUNCTION visible_namespace_ids(viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT id FROM namespace
  WHERE COALESCE(viewer_is_admin, false)
     OR visibility = 'public'
     OR owner_id = viewer_id
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION visible_namespace_ids(UUID, BOOLEAN) IS
    'Namespaces visible to a viewer. Set-returning form of sbom_visible(), for filtering rollup tables where the per-row form costs one EXISTS lookup per rollup row.';

-- +goose Down

-- Reverses cleanly on data that has not diverged from the 1:1 registry mapping
-- the Up created. It is best-effort beyond that, and deliberately so: once a
-- namespace holds two sources, or an upload source exists, there is no registry
-- row to put the ownership back on. Those cases are dropped rather than guessed
-- at — SBOMs from upload sources have their namespace_id set to NULL, matching
-- the pre-migration schema where an uploaded SBOM had no registry.

-- All three functions are dropped up front and recreated at the very end. A
-- LANGUAGE sql body is parsed and validated at CREATE time, so none of them can
-- be recreated until registry.visibility and registry.owner_id are back.
DROP FUNCTION IF EXISTS visible_namespace_ids(UUID, BOOLEAN);
DROP FUNCTION IF EXISTS artifact_visible(UUID, UUID, BOOLEAN);
DROP FUNCTION IF EXISTS sbom_visible(UUID, UUID, BOOLEAN);

-- Restore registry's identity and ownership columns before anything references
-- them again.
ALTER TABLE registry ADD COLUMN name TEXT;
ALTER TABLE registry ADD COLUMN owner_id UUID REFERENCES ocidex_user (id) ON DELETE SET NULL;
ALTER TABLE registry ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public';

UPDATE registry r
SET name       = s.name,
    owner_id   = n.owner_id,
    visibility = n.visibility
FROM source s
JOIN namespace n ON n.id = s.namespace_id
WHERE s.id = r.id;

ALTER TABLE registry ALTER COLUMN name SET NOT NULL;
ALTER TABLE registry ADD CONSTRAINT registry_name_key UNIQUE (name);
ALTER TABLE registry ADD CONSTRAINT registry_visibility_check
    CHECK (visibility IN ('public', 'private'));
ALTER TABLE registry DROP CONSTRAINT IF EXISTS registry_id_fkey;
CREATE INDEX IF NOT EXISTS idx_registry_owner_id ON registry (owner_id) WHERE owner_id IS NOT NULL;

-- Drop rows that have no registry to point back at (upload sources).
DELETE FROM component_rollup WHERE namespace_id NOT IN (SELECT id FROM registry);
DELETE FROM license_rollup   WHERE namespace_id NOT IN (SELECT id FROM registry);
DELETE FROM vuln_rollup      WHERE namespace_id NOT IN (SELECT id FROM registry);
DELETE FROM artifact_namespace WHERE namespace_id NOT IN (SELECT id FROM registry);
UPDATE sbom SET namespace_id = NULL WHERE namespace_id NOT IN (SELECT id FROM registry);

ALTER TABLE vuln_rollup DROP CONSTRAINT IF EXISTS vuln_rollup_namespace_id_fkey;
ALTER TABLE vuln_rollup RENAME COLUMN namespace_id TO registry_id;
ALTER TABLE vuln_rollup ADD CONSTRAINT vuln_rollup_registry_id_fkey
    FOREIGN KEY (registry_id) REFERENCES registry (id) ON DELETE CASCADE;

ALTER TABLE license_rollup DROP CONSTRAINT IF EXISTS license_rollup_namespace_id_fkey;
ALTER TABLE license_rollup RENAME COLUMN namespace_id TO registry_id;
ALTER TABLE license_rollup ADD CONSTRAINT license_rollup_registry_id_fkey
    FOREIGN KEY (registry_id) REFERENCES registry (id) ON DELETE CASCADE;

ALTER TABLE component_rollup DROP CONSTRAINT IF EXISTS component_rollup_namespace_id_fkey;
ALTER TABLE component_rollup RENAME COLUMN namespace_id TO registry_id;
ALTER TABLE component_rollup ADD CONSTRAINT component_rollup_registry_id_fkey
    FOREIGN KEY (registry_id) REFERENCES registry (id) ON DELETE CASCADE;

ALTER TABLE artifact_namespace DROP CONSTRAINT IF EXISTS artifact_namespace_namespace_id_fkey;
-- +goose StatementBegin
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint
             WHERE conname = 'artifact_namespace_artifact_id_fkey'
               AND conrelid = 'artifact_namespace'::regclass) THEN
    ALTER TABLE artifact_namespace RENAME CONSTRAINT artifact_namespace_artifact_id_fkey
        TO artifact_registry_artifact_id_fkey;
  END IF;
END $$;
-- +goose StatementEnd
ALTER INDEX IF EXISTS idx_artifact_namespace_namespace RENAME TO idx_artifact_registry_registry;
ALTER TABLE artifact_namespace RENAME TO artifact_registry;
ALTER TABLE artifact_registry RENAME COLUMN namespace_id TO registry_id;
ALTER TABLE artifact_registry ADD CONSTRAINT artifact_registry_registry_id_fkey
    FOREIGN KEY (registry_id) REFERENCES registry (id) ON DELETE CASCADE;

DROP INDEX IF EXISTS idx_sbom_source_id;
ALTER TABLE sbom DROP COLUMN source_id;
ALTER TABLE sbom DROP CONSTRAINT IF EXISTS sbom_namespace_id_fkey;
ALTER INDEX IF EXISTS idx_sbom_namespace_id RENAME TO idx_sbom_registry_id;
ALTER TABLE sbom RENAME COLUMN namespace_id TO registry_id;
ALTER TABLE sbom ADD CONSTRAINT sbom_registry_id_fkey
    FOREIGN KEY (registry_id) REFERENCES registry (id) ON DELETE SET NULL;

DROP TABLE IF EXISTS source;
DROP TABLE IF EXISTS namespace;

-- +goose StatementBegin
CREATE FUNCTION visible_registry_ids(viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT id FROM registry
  WHERE COALESCE(viewer_is_admin, false)
     OR visibility = 'public'
     OR owner_id = viewer_id
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION sbom_visible(reg_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR reg_id IS NULL
      OR EXISTS (
           SELECT 1 FROM registry
           WHERE id = reg_id
             AND (visibility = 'public' OR owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

-- +goose StatementBegin
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
-- +goose StatementEnd
