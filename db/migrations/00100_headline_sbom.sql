-- +goose Up

-- One definition of "the SBOM an artifact's figures are counted from", so the
-- artifact tile, the list row, the versions table, the featured cards and the
-- catalog maxima stop each picking their own. Every query that shows one
-- version's or one artifact's counts reads these functions instead of
-- ordering sbom itself.
--
-- The rule, in order:
--   1. only SBOMs in namespaces the viewer can see;
--   2. a stable version over a prerelease, unless there is no stable one;
--   3. the highest version by version parts;
--   4. between variants of equal version parts, the plain line, then variant
--      name: 3.15.2 over 3.15.2-alpine over 3.15.2-trixie. Ingest time never
--      decides between variants;
--   5. within the version, one architecture: amd64, then arm64, then the rest
--      alphabetically, then SBOMs with no known architecture;
--   6. ingest time, newest first, only among SBOMs that tie on all of that.
--
-- Steps 1-4 pick the version, steps 5-6 the SBOM within it. The version is
-- keyed the way the versions table keys it (sbom_version_key) so a digest-only
-- SBOM resolves to the same row there and here.

-- +goose StatementBegin
CREATE FUNCTION sbom_architecture(s_id UUID)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    (SELECT data->>'architecture' FROM enrichment
      WHERE sbom_id = s_id AND enricher_name = 'oci-metadata' AND status = 'success'),
    (SELECT data->>'architecture' FROM enrichment
      WHERE sbom_id = s_id AND enricher_name = 'user' AND status = 'success'))
$$;
-- +goose StatementEnd

-- Preference order of an architecture for counting a version: lower first.
-- Sort by the name as well to order the rest alphabetically.
-- +goose StatementBegin
CREATE FUNCTION sbom_arch_rank(arch TEXT)
RETURNS INT
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE
    WHEN arch = 'amd64' THEN 0
    WHEN arch = 'arm64' THEN 1
    WHEN arch IS NULL THEN 3
    ELSE 2
  END
$$;
-- +goose StatementEnd

-- The versions table's key for an SBOM: its subject version, else the image
-- version an enricher found, else the SBOM itself.
-- +goose StatementBegin
CREATE FUNCTION sbom_version_key(s_id UUID, subject_version TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    subject_version,
    (SELECT data->>'imageVersion' FROM enrichment
      WHERE sbom_id = s_id AND enricher_name = 'oci-metadata' AND status = 'success'),
    (SELECT data->>'imageVersion' FROM enrichment
      WHERE sbom_id = s_id AND enricher_name = 'user' AND status = 'success'),
    s_id::text)
$$;
-- +goose StatementEnd

-- The SBOM one version is counted from (steps 1, 5 and 6). NULL when the
-- viewer can see none of the version's SBOMs.
-- +goose StatementBegin
CREATE FUNCTION version_headline_sbom(a_id UUID, version_key TEXT, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
  SELECT s.id
  FROM sbom s
  CROSS JOIN LATERAL (SELECT sbom_architecture(s.id) AS arch) x
  WHERE s.artifact_id = a_id
    -- A non-null subject version is its own key, so only SBOMs without one
    -- need the key computed.
    AND (s.subject_version = version_key OR s.subject_version IS NULL)
    AND sbom_version_key(s.id, s.subject_version) = version_key
    AND s.namespace_id IN (SELECT visible_namespace_ids(viewer_id, viewer_is_admin))
  ORDER BY sbom_arch_rank(x.arch), x.arch, s.created_at DESC, s.id DESC
  LIMIT 1
$$;
-- +goose StatementEnd

-- The SBOM an artifact is counted from (all six steps). NULL when the viewer
-- can see none of its SBOMs.
-- +goose StatementBegin
CREATE FUNCTION artifact_headline_sbom(a_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
  SELECT version_headline_sbom(a_id, sbom_version_key(top.id, top.subject_version), viewer_id, viewer_is_admin)
  FROM (
    SELECT s.id, s.subject_version
    FROM sbom s
    WHERE s.artifact_id = a_id
      AND s.namespace_id IN (SELECT visible_namespace_ids(viewer_id, viewer_is_admin))
    ORDER BY s.version_prerelease,
             s.version_major DESC NULLS LAST,
             s.version_minor DESC NULLS LAST,
             s.version_patch DESC NULLS LAST,
             s.version_variant <> '',
             s.version_variant,
             s.created_at DESC, s.id DESC
    LIMIT 1
  ) top
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS artifact_headline_sbom(UUID, UUID, BOOLEAN);
DROP FUNCTION IF EXISTS version_headline_sbom(UUID, TEXT, UUID, BOOLEAN);
DROP FUNCTION IF EXISTS sbom_version_key(UUID, TEXT);
DROP FUNCTION IF EXISTS sbom_arch_rank(TEXT);
DROP FUNCTION IF EXISTS sbom_architecture(UUID);
