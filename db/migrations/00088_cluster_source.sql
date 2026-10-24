-- +goose Up
-- ADR-0044 K10: a running image no registry claims is attributed to the cluster
-- that reported it. Every cluster gets a source of kind 'cluster' that shares
-- its id, as an oci_registry source shares its registry's id (ADR-039), and
-- lives in the cluster's namespace. Triggers keep the row in step with the
-- cluster, so no write path can create a cluster without one.
ALTER TABLE source DROP CONSTRAINT source_kind_check;
ALTER TABLE source ADD CONSTRAINT source_kind_check
    CHECK (kind IN ('oci_registry', 'upload', 'cluster'));

COMMENT ON TABLE source IS
    'How an SBOM reached OCIDex. kind is the subtype discriminator; an oci_registry source has a matching registry row, a cluster source a matching cluster row (same id), an upload source neither.';

INSERT INTO source (id, namespace_id, kind, name, created_at, updated_at)
SELECT id, namespace_id, 'cluster', 'cluster:' || name, created_at, updated_at FROM cluster;

-- +goose StatementBegin
CREATE FUNCTION cluster_source_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO source (id, namespace_id, kind, name)
        VALUES (NEW.id, NEW.namespace_id, 'cluster', 'cluster:' || NEW.name);
    ELSIF TG_OP = 'UPDATE' THEN
        UPDATE source SET name = 'cluster:' || NEW.name, updated_at = now()
        WHERE id = NEW.id AND kind = 'cluster';
    ELSE
        DELETE FROM source WHERE id = OLD.id AND kind = 'cluster';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER cluster_source_insert AFTER INSERT ON cluster
    FOR EACH ROW EXECUTE FUNCTION cluster_source_sync();
CREATE TRIGGER cluster_source_rename AFTER UPDATE OF name ON cluster
    FOR EACH ROW WHEN (OLD.name IS DISTINCT FROM NEW.name) EXECUTE FUNCTION cluster_source_sync();
CREATE TRIGGER cluster_source_delete AFTER DELETE ON cluster
    FOR EACH ROW EXECUTE FUNCTION cluster_source_sync();

-- registry_id keeps meaning whose credentials the pull uses, and is NULL for an
-- anonymous pull. cluster_id, when set, is the job's attribution: the SBOM's
-- source. registry_host is where an anonymous job pulls from, since it has no
-- registry row to read a URL off. A cluster's jobs go with it.
ALTER TABLE scan_jobs
    ADD COLUMN cluster_id    UUID NULL REFERENCES cluster (id) ON DELETE CASCADE,
    ADD COLUMN registry_host TEXT NULL;
CREATE INDEX idx_scan_jobs_cluster_id ON scan_jobs (cluster_id) WHERE cluster_id IS NOT NULL;

-- Cluster ingest looks up existing jobs by the digests a cluster reports, which
-- are platform digests or index digests.
CREATE INDEX idx_scan_jobs_digest       ON scan_jobs (digest);
CREATE INDEX idx_scan_jobs_index_digest ON scan_jobs (index_digest) WHERE index_digest IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_scan_jobs_index_digest;
DROP INDEX IF EXISTS idx_scan_jobs_digest;
DROP INDEX IF EXISTS idx_scan_jobs_cluster_id;
DELETE FROM scan_jobs WHERE cluster_id IS NOT NULL OR (registry_id IS NULL AND registry_host IS NOT NULL);
ALTER TABLE scan_jobs DROP COLUMN registry_host, DROP COLUMN cluster_id;

DROP TRIGGER IF EXISTS cluster_source_delete ON cluster;
DROP TRIGGER IF EXISTS cluster_source_rename ON cluster;
DROP TRIGGER IF EXISTS cluster_source_insert ON cluster;
DROP FUNCTION IF EXISTS cluster_source_sync();

DELETE FROM source WHERE kind = 'cluster';
ALTER TABLE source DROP CONSTRAINT source_kind_check;
ALTER TABLE source ADD CONSTRAINT source_kind_check
    CHECK (kind IN ('oci_registry', 'upload'));
COMMENT ON TABLE source IS
    'How an SBOM reached OCIDex. kind is the subtype discriminator; an oci_registry source has a matching registry row, an upload source has none.';
