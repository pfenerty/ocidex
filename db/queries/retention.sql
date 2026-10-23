-- Retention candidates and deletes (ADR-0056). Every query excludes
-- sbom_retention_protected (R4), which holds the protected set. A registry SBOM
-- is one whose source is an oci_registry; class N never touches them.

-- name: ListRetentionNewestCandidates :many
-- Class N (R3): non-registry SBOMs whose version is past the newest @keep_last
-- in its series, or, when @cutoff is set, was ingested before it. Oldest first.
WITH versions AS (
    SELECT s.namespace_id,
           COALESCE(s.artifact_id, s.id)          AS series,
           COALESCE(s.flavor, 'unknown')          AS flavor,
           COALESCE(s.subject_version, s.id::text) AS version,
           max(s.created_at)                      AS ingested
    FROM sbom s
    WHERE NOT EXISTS (SELECT 1 FROM source src WHERE src.id = s.source_id AND src.kind = 'oci_registry')
    GROUP BY 1, 2, 3, 4
),
ranked AS (
    SELECT v.*,
           row_number() OVER (PARTITION BY namespace_id, series, flavor ORDER BY ingested DESC, version DESC) AS rank
    FROM versions v
)
SELECT s.id
FROM sbom s
JOIN ranked r
  ON r.namespace_id = s.namespace_id
 AND r.series = COALESCE(s.artifact_id, s.id)
 AND r.flavor = COALESCE(s.flavor, 'unknown')
 AND r.version = COALESCE(s.subject_version, s.id::text)
WHERE (r.rank > @keep_last::bigint OR r.ingested < sqlc.narg('cutoff')::timestamptz)
  AND NOT EXISTS (SELECT 1 FROM source src WHERE src.id = s.source_id AND src.kind = 'oci_registry')
  AND s.id NOT IN (SELECT id FROM sbom_retention_protected)
ORDER BY r.ingested, s.id
LIMIT @row_limit;

-- name: ListRetentionWindowCandidates :many
-- Class W (R2): registry SBOMs from a repository the last successful walk
-- covered, whose image that walk did not select. An SBOM with no registry scan
-- job, or from a repository with no window row, is never a candidate.
SELECT s.id
FROM sbom s
JOIN source src ON src.id = s.source_id AND src.kind = 'oci_registry'
JOIN LATERAL (
    SELECT j.registry_id, j.repository
    FROM scan_jobs j
    WHERE j.sbom_id = s.id AND j.registry_id IS NOT NULL
    ORDER BY j.created_at DESC
    LIMIT 1
) j ON true
JOIN registry_window w ON w.registry_id = j.registry_id AND w.repository = j.repository
WHERE NOT (COALESCE(s.index_digest, s.digest) = ANY (w.digests))
  AND s.id NOT IN (SELECT id FROM sbom_retention_protected)
ORDER BY s.created_at, s.id
LIMIT @row_limit;

-- name: DeleteRetentionBatch :execrows
-- Deletes candidates, checking the protected set again (R6): an SBOM that
-- started running or picked up an enrichment job since it was listed stays.
DELETE FROM sbom
WHERE id = ANY (@ids::uuid[])
  AND id NOT IN (SELECT id FROM sbom_retention_protected);
