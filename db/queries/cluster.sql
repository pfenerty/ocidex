-- Kubernetes deployment inventory (ADR-044).
--
-- A cluster is owned by a namespace and has no visibility of its own, so every
-- read path here resolves visibility through `namespace` exactly as source.sql
-- does. Nothing in this file may be called without a visibility gate either in
-- the query or at the service boundary; the comment on each read says which.

-- name: CreateCluster :one
INSERT INTO cluster (namespace_id, name, description)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetCluster :one
SELECT * FROM cluster WHERE id = $1;

-- name: GetClusterByName :one
SELECT * FROM cluster WHERE namespace_id = $1 AND name = $2;

-- name: ListClustersByNamespace :many
SELECT * FROM cluster WHERE namespace_id = $1 ORDER BY created_at ASC;

-- name: ListClusters :many
-- Visibility resolved through the owning namespace; owned_only switches to the
-- ownership path. Same two-paths-one-query shape as ListSources and
-- ListNamespaces — see ListNamespaces for why they are not split.
SELECT sqlc.embed(c), n.name AS namespace_name, n.owner_id, n.visibility
FROM cluster c
JOIN namespace n ON n.id = c.namespace_id
WHERE (
    CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
         THEN n.owner_id = sqlc.narg('user_id')::uuid
         ELSE sqlc.narg('is_admin')::boolean = true
              OR n.visibility = 'public'
              OR (sqlc.narg('user_id')::uuid IS NOT NULL AND n.owner_id = sqlc.narg('user_id')::uuid)
    END
)
ORDER BY c.created_at ASC;

-- name: UpdateCluster :one
UPDATE cluster
SET name        = $2,
    description = $3,
    updated_at  = now()
WHERE id = $1
RETURNING *;

-- name: DeleteCluster :execrows
-- Cascades to cluster_workload. Inventory is derived state reported by an
-- agent, so losing it with the cluster is correct.
DELETE FROM cluster WHERE id = $1;

-- name: TouchClusterLastSeen :exec
-- Stamped once per accepted snapshot, inside the ingest transaction. This is
-- what makes "dead agent" distinguishable from "empty cluster" (ADR-044 K2).
UPDATE cluster SET last_seen_at = $2, updated_at = now() WHERE id = $1;

-- name: UpsertClusterWorkload :exec
-- One row of a snapshot. The conflict target is the full natural key including
-- image_digest, so a rollout running two digests of one container yields two
-- rows rather than one overwriting the other.
--
-- first_seen_at is deliberately absent from the UPDATE set: it is the one field
-- that must survive re-reporting, and "running since" is the only history this
-- current-state table keeps.
INSERT INTO cluster_workload (
    cluster_id, k8s_namespace, workload_kind, workload_name, container_name,
    image_ref, image_digest, pod_count, first_seen_at, last_seen_at
)
VALUES ($1, $2, $3, $4, $5, $6, sqlc.narg('image_digest')::text, $7, @observed_at, @observed_at)
ON CONFLICT (cluster_id, k8s_namespace, workload_kind, workload_name, container_name, image_digest)
DO UPDATE SET
    image_ref    = EXCLUDED.image_ref,
    pod_count    = EXCLUDED.pod_count,
    last_seen_at = EXCLUDED.last_seen_at;

-- name: PruneClusterWorkloads :execrows
-- The second half of full-snapshot semantics (ADR-044 K7). Every row the
-- snapshot touched carries the snapshot's observed_at; anything older was not
-- reported and is therefore no longer running.
--
-- Strictly `<`, not `<>`: a concurrent later snapshot must not have its rows
-- deleted by an older one still committing.
DELETE FROM cluster_workload
WHERE cluster_id = $1 AND last_seen_at < @observed_at;

-- name: ListClusterWorkloads :many
-- The payoff join (ADR-044 K4/K5). match_state is a single NOT NULL enum-ish
-- column carrying all four outcomes:
--
--   'exact'        — image_digest = sbom.digest, a per-platform match.
--   'index'        — image_digest = sbom.index_digest, i.e. the workload runs
--                    some platform of a scanned multi-arch image. One-to-many by
--                    nature, so the newest such SBOM is chosen deterministically.
--   'unknown'      — a valid digest matching no ingested SBOM: a coverage gap.
--   'unresolvable' — no digest could be read from imageID: an agent/runtime gap.
--
-- It is deliberately not a nullable match_tier. A NULL is trivially ignored by a
-- caller, and the one thing this feature must never do is let a workload with no
-- SBOM render the same as a matched workload with zero vulnerabilities (K5).
-- Making the state non-null means every consumer has to name the case.
--
-- Visibility is enforced here, not by the caller: the cluster's namespace must
-- be visible. The matched SBOM is NOT re-filtered — a workload's own cluster
-- being visible is the authorization for seeing what it runs, and hiding the
-- match would report a coverage gap that does not exist.
SELECT
    sqlc.embed(w),
    s.id            AS sbom_id,
    s.artifact_id   AS artifact_id,
    s.subject_version AS subject_version,
    a.name          AS artifact_name,
    a.type          AS artifact_type,
    (CASE WHEN s.id IS NOT NULL AND s.digest = w.image_digest THEN 'exact'
          WHEN s.id IS NOT NULL                               THEN 'index'
          WHEN w.image_digest IS NULL                         THEN 'unresolvable'
          ELSE                                                     'unknown'
     END)::text     AS match_state
FROM cluster_workload w
JOIN cluster c ON c.id = w.cluster_id
LEFT JOIN LATERAL (
    SELECT s2.id, s2.artifact_id, s2.subject_version, s2.digest
    FROM sbom s2
    WHERE w.image_digest IS NOT NULL
      AND (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
    ORDER BY (s2.digest = w.image_digest) DESC, s2.created_at DESC
    LIMIT 1
) s ON true
LEFT JOIN artifact a ON a.id = s.artifact_id
WHERE w.cluster_id = $1
  AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
ORDER BY w.k8s_namespace ASC, w.workload_name ASC, w.container_name ASC;

-- name: GetClusterWorkloadCoverage :one
-- The counts that must accompany any vulnerability figure reported over running
-- workloads (ADR-044 K5). Without these, "3 criticals running" is misleadingly
-- reassuring — it silently omits every workload OCIDex could not match.
SELECT
    COUNT(*)                                                            AS total,
    COUNT(*) FILTER (WHERE w.image_digest IS NULL)                      AS unresolvable,
    COUNT(*) FILTER (WHERE w.image_digest IS NOT NULL AND s.id IS NULL) AS unknown,
    COUNT(*) FILTER (WHERE s.id IS NOT NULL)                            AS matched
FROM cluster_workload w
JOIN cluster c ON c.id = w.cluster_id
LEFT JOIN LATERAL (
    SELECT s2.id
    FROM sbom s2
    WHERE w.image_digest IS NOT NULL
      AND (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
    LIMIT 1
) s ON true
WHERE w.cluster_id = $1
  AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean));

-- name: ListClusterRunningVulns :many
-- Vulnerabilities scoped to images actually running in one cluster — the view
-- the whole epic exists for.
--
-- Rows are keyed by canonical_id, not by vulnerability.id: OSV publishes the
-- same finding under several native ids (GO-… and GHSA-… both aliasing one
-- CVE), and listing each of them separately would report one problem three
-- times. The representative row is the highest-severity member of the alias
-- group, which is also the one the UI links to.
--
-- Workloads are counted DISTINCT across the whole alias group, so "affects 3
-- running workloads" is a number a user can act on rather than a count of
-- component rows.
--
-- Read alongside GetClusterWorkloadCoverage, never alone.
WITH running AS (
    SELECT
        COALESCE(NULLIF(v.canonical_id, ''), v.id) AS canonical_id,
        w.id                                       AS workload_id
    FROM cluster_workload w
    JOIN cluster c ON c.id = w.cluster_id
    JOIN LATERAL (
        SELECT s2.id
        FROM sbom s2
        WHERE w.image_digest IS NOT NULL
          AND (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
        ORDER BY (s2.digest = w.image_digest) DESC, s2.created_at DESC
        LIMIT 1
    ) s ON true
    JOIN component comp ON comp.sbom_id = s.id AND comp.purl IS NOT NULL
    JOIN package_vulnerability pv ON pv.purl = comp.purl
    JOIN vulnerability v ON v.id = pv.vulnerability_id
    WHERE w.cluster_id = $1
      AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
),
counts AS (
    SELECT canonical_id, COUNT(DISTINCT workload_id)::bigint AS workload_count
    FROM running
    GROUP BY canonical_id
),
canonical AS (
    SELECT DISTINCT ON (COALESCE(NULLIF(v.canonical_id, ''), v.id))
        v.id,
        COALESCE(NULLIF(v.canonical_id, ''), v.id) AS canonical_id,
        v.severity,
        v.cvss_score,
        v.summary
    FROM vulnerability v
    WHERE COALESCE(NULLIF(v.canonical_id, ''), v.id) IN (SELECT canonical_id FROM counts)
    ORDER BY
        COALESCE(NULLIF(v.canonical_id, ''), v.id),
        CASE v.severity
            WHEN 'CRITICAL' THEN 4
            WHEN 'HIGH'     THEN 3
            WHEN 'MEDIUM'   THEN 2
            WHEN 'LOW'      THEN 1
            ELSE 0
        END DESC,
        v.cvss_score DESC NULLS LAST
)
SELECT
    cv.id,
    cv.canonical_id,
    cv.severity,
    cv.cvss_score,
    cv.summary,
    k.workload_count
FROM canonical cv
JOIN counts k ON k.canonical_id = cv.canonical_id
WHERE (sqlc.narg('severity')::text IS NULL OR cv.severity = sqlc.narg('severity')::text)
ORDER BY
    CASE cv.severity
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH'     THEN 3
        WHEN 'MEDIUM'   THEN 2
        WHEN 'LOW'      THEN 1
        ELSE 0
    END DESC,
    cv.cvss_score DESC NULLS LAST,
    cv.canonical_id ASC
LIMIT sqlc.narg('limit')::int OFFSET sqlc.narg('offset')::int;

-- name: CountClusterRunningVulns :one
-- The total for ListClusterRunningVulns' pagination, counted over the same
-- canonical_id grouping so the total and the page agree about what one row is.
WITH running AS (
    SELECT
        COALESCE(NULLIF(v.canonical_id, ''), v.id) AS canonical_id,
        v.severity                                 AS severity
    FROM cluster_workload w
    JOIN cluster c ON c.id = w.cluster_id
    JOIN LATERAL (
        SELECT s2.id
        FROM sbom s2
        WHERE w.image_digest IS NOT NULL
          AND (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
        ORDER BY (s2.digest = w.image_digest) DESC, s2.created_at DESC
        LIMIT 1
    ) s ON true
    JOIN component comp ON comp.sbom_id = s.id AND comp.purl IS NOT NULL
    JOIN package_vulnerability pv ON pv.purl = comp.purl
    JOIN vulnerability v ON v.id = pv.vulnerability_id
    WHERE w.cluster_id = $1
      AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
)
SELECT COUNT(DISTINCT canonical_id)::bigint AS total
FROM running
WHERE (sqlc.narg('severity')::text IS NULL OR severity = sqlc.narg('severity')::text);

-- name: ListWorkloadsForVulnerability :many
-- The reverse of ListClusterRunningVulns: given a vulnerability, which running
-- workloads carry it. "These three Deployments have CVE-X" in one query.
--
-- Keyed by canonical_id rather than vulnerability.id for two reasons: it is
-- what travels in the URL (/vulns/{canonical}/workloads), and matching the id
-- alone would miss workloads affected through a sibling alias record.
--
-- cluster_id is optional. Passed, this is the cluster page's drill-down; NULL,
-- it answers "where is this CVE running anywhere I can see", which is the
-- question the catalogue's vulnerability page cannot otherwise answer.
SELECT
    sqlc.embed(w),
    c.id            AS cluster_id_out,
    c.name          AS cluster_name,
    s.id            AS sbom_id,
    s.artifact_id   AS artifact_id,
    s.subject_version AS subject_version,
    a.name          AS artifact_name,
    -- Matched by construction here (the LATERAL join is inner), but which tier
    -- still has to be reported: an index match means the running platform is
    -- unknown, and a caller must be able to say so rather than imply an exact
    -- per-platform match it does not have (ADR-044 K4).
    (CASE WHEN s.digest = w.image_digest THEN 'exact' ELSE 'index' END)::text AS match_state
FROM cluster_workload w
JOIN cluster c ON c.id = w.cluster_id
JOIN LATERAL (
    SELECT s2.id, s2.artifact_id, s2.subject_version, s2.digest
    FROM sbom s2
    WHERE w.image_digest IS NOT NULL
      AND (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
    ORDER BY (s2.digest = w.image_digest) DESC, s2.created_at DESC
    LIMIT 1
) s ON true
LEFT JOIN artifact a ON a.id = s.artifact_id
WHERE EXISTS (
    SELECT 1
    FROM component comp
    JOIN package_vulnerability pv ON pv.purl = comp.purl
    JOIN vulnerability v ON v.id = pv.vulnerability_id
    WHERE comp.sbom_id = s.id
      AND comp.purl IS NOT NULL
      AND COALESCE(NULLIF(v.canonical_id, ''), v.id) = @canonical_id::text
)
  AND (sqlc.narg('cluster_id')::uuid IS NULL OR w.cluster_id = sqlc.narg('cluster_id')::uuid)
  AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
ORDER BY c.name ASC, w.k8s_namespace ASC, w.workload_name ASC
LIMIT sqlc.narg('limit')::int;
