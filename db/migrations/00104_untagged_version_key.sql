-- +goose Up

-- An SBOM with no subject version and no image version an enricher found (a
-- digest-only scan) used to be keyed by its own id, so every one was a
-- separate "version": they inflated version counts and showed UUIDs in the
-- versions table. They now share one key, '(untagged)'. Parentheses cannot
-- appear in an OCI tag, so the key cannot collide with a real version.
-- ListArtifactVersions, CountArtifactVersions and the artifact vulnerability
-- queries spell the same fallback inline.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sbom_version_key(s_id UUID, subject_version TEXT)
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
    '(untagged)')
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sbom_version_key(s_id UUID, subject_version TEXT)
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
