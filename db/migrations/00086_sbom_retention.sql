-- +goose Up
-- registry_window holds, per registry and repository, the top-level digests the
-- last successful walk's window selected (ADR-0056 R2). Retention prunes a
-- registry SBOM only from a repository with a row here, and only when its
-- coalesce(index_digest, digest) is not among the row's digests. Each
-- successful walk replaces the registry's rows; a failed walk leaves them.
CREATE TABLE registry_window (
    registry_id UUID        NOT NULL REFERENCES registry(id) ON DELETE CASCADE,
    repository  TEXT        NOT NULL,
    digests     TEXT[]      NOT NULL DEFAULT '{}',
    walked_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (registry_id, repository)
);

-- sbom_retention_protected is ADR-0056 R4, the SBOMs no retention class may
-- delete. The candidate queries exclude it and the delete checks it again, so
-- the rules live in one place.
--
-- A series is (namespace_id, artifact_id, flavor) and a version one
-- subject_version within it, ordered by its newest SBOM's created_at. An SBOM
-- with no artifact or no version stands alone, so it is the newest of its own
-- series.
--
-- P1: every SBOM of each series' newest version, and of its highest semver
--     version. Prerelease precedence is approximated: a release outranks its
--     prereleases, and prereleases of one release tie and fall to ingest time.
-- P2: any SBOM whose digest or index digest runs in any cluster.
-- P3: any SBOM ingested in the last 24 hours or with an open enrichment job.
CREATE VIEW sbom_retention_protected AS
WITH versions AS (
    SELECT namespace_id,
           COALESCE(artifact_id, id)          AS series,
           COALESCE(flavor, 'unknown')        AS flavor,
           COALESCE(subject_version, id::text) AS version,
           max(created_at)                    AS ingested
    FROM sbom
    GROUP BY 1, 2, 3, 4
),
newest AS (
    SELECT DISTINCT ON (namespace_id, series, flavor) namespace_id, series, flavor, version
    FROM versions
    ORDER BY namespace_id, series, flavor, ingested DESC, version DESC
),
semver AS (
    SELECT DISTINCT ON (namespace_id, series, flavor) namespace_id, series, flavor, version
    FROM (
        SELECT v.*,
               regexp_match(v.version, '^v?(\d+)\.(\d+)\.(\d+)(-[A-Za-z0-9.]+)?(\+[A-Za-z0-9.]+)?$') AS m
        FROM versions v
    ) parsed
    WHERE m IS NOT NULL
    ORDER BY namespace_id, series, flavor,
             m[1]::numeric DESC, m[2]::numeric DESC, m[3]::numeric DESC,
             (m[4] IS NULL) DESC, ingested DESC, version DESC
)
SELECT s.id
FROM sbom s
JOIN (SELECT * FROM newest UNION SELECT * FROM semver) k
  ON k.namespace_id = s.namespace_id
 AND k.series = COALESCE(s.artifact_id, s.id)
 AND k.flavor = COALESCE(s.flavor, 'unknown')
 AND k.version = COALESCE(s.subject_version, s.id::text)
UNION
SELECT s.id
FROM sbom s
JOIN cluster_workload w ON w.image_digest = s.digest OR w.image_digest = s.index_digest
UNION
SELECT id FROM sbom WHERE created_at > now() - interval '24 hours'
UNION
SELECT sbom_id FROM enrichment_jobs WHERE state IN ('queued', 'running');

-- +goose Down
DROP VIEW IF EXISTS sbom_retention_protected;
DROP TABLE IF EXISTS registry_window;
