-- Scope SBOM uniqueness to the namespace. Each namespace keeps its own SBOM for
-- an image digest (and for a serial number/version): ingest dedupes within the
-- ingesting namespace only, and a row in one namespace never blocks or resolves
-- to another namespace's.

-- +goose Up
DROP INDEX IF EXISTS idx_sbom_digest;
CREATE INDEX idx_sbom_digest ON sbom (digest) WHERE digest IS NOT NULL;
CREATE UNIQUE INDEX idx_sbom_namespace_digest ON sbom (namespace_id, digest) WHERE digest IS NOT NULL;
DROP INDEX IF EXISTS idx_sbom_serial_version;
CREATE UNIQUE INDEX idx_sbom_serial_version
    ON sbom (namespace_id, serial_number, version)
    WHERE serial_number IS NOT NULL;

-- The namespaces whose SBOMs a cluster's workloads may match by digest: the
-- cluster's own namespace and public namespaces. Callers prefer the cluster's
-- own namespace when both have one.
-- +goose StatementBegin
CREATE FUNCTION cluster_sbom_namespace_ids(cluster_namespace_id UUID)
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT n.id FROM namespace n
  WHERE n.id = cluster_namespace_id
     OR n.visibility = 'public'
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS cluster_sbom_namespace_ids(UUID);
DROP INDEX IF EXISTS idx_sbom_serial_version;
CREATE UNIQUE INDEX idx_sbom_serial_version
    ON sbom (serial_number, version)
    WHERE serial_number IS NOT NULL;
DROP INDEX IF EXISTS idx_sbom_namespace_digest;
DROP INDEX IF EXISTS idx_sbom_digest;
CREATE UNIQUE INDEX idx_sbom_digest ON sbom (digest) WHERE digest IS NOT NULL;
