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
-- auto_ingest is a narg rather than a plain column: a PATCH that only renames
-- the cluster must not silently switch ingest off by omitting the field.
UPDATE cluster
SET name        = $2,
    description = $3,
    auto_ingest = COALESCE(sqlc.narg('auto_ingest')::boolean, auto_ingest),
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
-- The state is computed in a LATERAL rather than inline so the projection and
-- the match_state filter below read the same expression. Two copies of a CASE
-- this load-bearing would eventually disagree, and a filter that disagreed with
-- the column it filters is invisible until someone counts the rows.
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
    ms.state        AS match_state,
    COALESCE(vs.critical, 0)::bigint AS critical_count,
    COALESCE(vs.high, 0)::bigint     AS high_count,
    COALESCE(vs.medium, 0)::bigint   AS medium_count,
    COALESCE(vs.low, 0)::bigint      AS low_count
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
CROSS JOIN LATERAL (
    SELECT (CASE WHEN s.id IS NOT NULL AND s.digest = w.image_digest THEN 'exact'
                 WHEN s.id IS NOT NULL                               THEN 'index'
                 WHEN w.image_digest IS NULL                         THEN 'unresolvable'
                 ELSE                                                     'unknown'
            END)::text AS state
) ms
-- Per-severity finding counts for the matched SBOM, so "which images have
-- vulnerabilities" is answerable from the table instead of by fanning out one
-- request per row from the browser. Counts distinct canonical_ids, matching
-- GetSBOMVulnSummary, so an alias group is one finding here too.
--
-- The join is LEFT ... ON s.id IS NOT NULL, so an unmatched workload produces
-- no counts at all. They are projected through COALESCE only because a NULL
-- bigint out of a lateral aggregate is not something sqlc can type; the
-- zero it yields for an unmatched row is not a finding count and must never be
-- read as one. match_state is the column that says which, and it is non-null
-- precisely so every consumer has to name the case (K5) — the service layer
-- drops the counts entirely for a workload that never matched.
--
-- The sort term below reads vs.* directly rather than the coalesced projection,
-- so an unassessed workload sorts last in both directions instead of ranking
-- alongside a clean one.
LEFT JOIN LATERAL (
    SELECT
        COUNT(DISTINCT COALESCE(NULLIF(v.canonical_id, ''), v.id))
            FILTER (WHERE v.severity = 'CRITICAL')::bigint AS critical,
        COUNT(DISTINCT COALESCE(NULLIF(v.canonical_id, ''), v.id))
            FILTER (WHERE v.severity = 'HIGH')::bigint     AS high,
        COUNT(DISTINCT COALESCE(NULLIF(v.canonical_id, ''), v.id))
            FILTER (WHERE v.severity = 'MEDIUM')::bigint   AS medium,
        COUNT(DISTINCT COALESCE(NULLIF(v.canonical_id, ''), v.id))
            FILTER (WHERE v.severity = 'LOW')::bigint      AS low
    FROM (SELECT DISTINCT purl FROM component WHERE sbom_id = s.id AND purl IS NOT NULL) comp
    JOIN package_vulnerability pv ON pv.purl = comp.purl
    JOIN vulnerability v ON v.id = pv.vulnerability_id
) vs ON s.id IS NOT NULL
WHERE w.cluster_id = $1
  AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
  AND (sqlc.narg('k8s_namespace')::text IS NULL OR w.k8s_namespace = sqlc.narg('k8s_namespace')::text)
  AND (sqlc.narg('match_state')::text IS NULL OR ms.state = sqlc.narg('match_state')::text)
  AND (sqlc.narg('q')::text IS NULL OR (
        w.workload_name  ILIKE '%' || sqlc.narg('q')::text || '%'
     OR w.container_name ILIKE '%' || sqlc.narg('q')::text || '%'
     OR w.image_ref      ILIKE '%' || sqlc.narg('q')::text || '%'))
-- Sorting is parameterised because the list is server-paginated: reordering
-- only the rows that happen to be on the current page would misrepresent the
-- whole cluster (same argument as ListTopVulnerabilities).
ORDER BY
    -- Numeric keys share one term; the direction flips the sign.
    CASE @sort_by::text
        WHEN 'pod_count'    THEN w.pod_count::float8
        WHEN 'last_seen_at' THEN EXTRACT(EPOCH FROM w.last_seen_at)::float8
        -- Severity counts packed into one number, most severe most
        -- significant, so "worst first" is one sort rather than four. NULL
        -- (never assessed) stays NULL and sorts last in both directions —
        -- an unassessed workload must not rank alongside a clean one.
        WHEN 'vuln_count'   THEN (vs.critical * 1000000 + vs.high * 1000 + vs.medium)::float8
    END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
    -- Text keys can't ride the sign trick, but they can share one nested CASE
    -- per direction instead of two terms per key.
    CASE WHEN @sort_dir::text = 'asc' THEN
        CASE @sort_by::text
            WHEN 'k8s_namespace'  THEN w.k8s_namespace
            WHEN 'workload_name'  THEN w.workload_name
            WHEN 'container_name' THEN w.container_name
            WHEN 'image_ref'      THEN w.image_ref
            WHEN 'match_state'    THEN ms.state
        END
    END ASC NULLS LAST,
    CASE WHEN @sort_dir::text = 'desc' THEN
        CASE @sort_by::text
            WHEN 'k8s_namespace'  THEN w.k8s_namespace
            WHEN 'workload_name'  THEN w.workload_name
            WHEN 'container_name' THEN w.container_name
            WHEN 'image_ref'      THEN w.image_ref
            WHEN 'match_state'    THEN ms.state
        END
    END DESC NULLS LAST,
    -- The default ordering, and the tiebreaker under every other key: without
    -- a total order, two pages of an offset-paginated list can repeat a row.
    w.k8s_namespace ASC, w.workload_name ASC, w.container_name ASC
LIMIT sqlc.narg('limit')::int OFFSET sqlc.narg('offset')::int;

-- name: CountClusterWorkloads :one
-- The total for ListClusterWorkloads' pagination. It takes the same filters, and
-- only the filters — it is the size of the filtered list, never a substitute for
-- GetClusterWorkloadCoverage, which is deliberately unfiltered.
SELECT COUNT(*)::bigint AS total
FROM cluster_workload w
JOIN cluster c ON c.id = w.cluster_id
LEFT JOIN LATERAL (
    SELECT s2.id, s2.digest
    FROM sbom s2
    WHERE w.image_digest IS NOT NULL
      AND (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
    ORDER BY (s2.digest = w.image_digest) DESC, s2.created_at DESC
    LIMIT 1
) s ON true
CROSS JOIN LATERAL (
    SELECT (CASE WHEN s.id IS NOT NULL AND s.digest = w.image_digest THEN 'exact'
                 WHEN s.id IS NOT NULL                               THEN 'index'
                 WHEN w.image_digest IS NULL                         THEN 'unresolvable'
                 ELSE                                                     'unknown'
            END)::text AS state
) ms
WHERE w.cluster_id = $1
  AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
  AND (sqlc.narg('k8s_namespace')::text IS NULL OR w.k8s_namespace = sqlc.narg('k8s_namespace')::text)
  AND (sqlc.narg('match_state')::text IS NULL OR ms.state = sqlc.narg('match_state')::text)
  AND (sqlc.narg('q')::text IS NULL OR (
        w.workload_name  ILIKE '%' || sqlc.narg('q')::text || '%'
     OR w.container_name ILIKE '%' || sqlc.narg('q')::text || '%'
     OR w.image_ref      ILIKE '%' || sqlc.narg('q')::text || '%'));

-- name: ListClusterK8sNamespaces :many
-- The namespace facet for the workload filter. It exists because the list is
-- paginated: the set of namespaces present in the cluster is not derivable from
-- one page of rows, and a filter that only offers the values on the current page
-- silently hides the rest of the cluster.
SELECT
    w.k8s_namespace,
    COUNT(*)::bigint AS workload_count
FROM cluster_workload w
JOIN cluster c ON c.id = w.cluster_id
WHERE w.cluster_id = $1
  AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
GROUP BY w.k8s_namespace
ORDER BY w.k8s_namespace ASC;

-- name: ListClusterUnknownImages :many
-- The No-SBOM gap, grouped by image rather than by container.
--
-- The workload table lists containers, but the remedy is per image: twelve
-- replicas of one unscanned image are one thing to ingest, not twelve. Grouping
-- here rather than in the browser also means the count is the whole cluster's,
-- not the current page's.
--
-- Only rows with a readable digest are included. A NULL digest is the
-- 'unresolvable' state, which no amount of ingesting will fix, and folding the
-- two together would offer an action that cannot work (ADR-044 K3/K5).
SELECT
    w.image_ref,
    w.image_digest::text                     AS image_digest,
    COUNT(*)::bigint                         AS workload_count,
    SUM(w.pod_count)::bigint                 AS pod_count,
    MIN(w.k8s_namespace)::text               AS sample_k8s_namespace,
    MIN(w.workload_name)::text               AS sample_workload_name,
    MAX(w.last_seen_at)::timestamptz         AS last_seen_at
FROM cluster_workload w
JOIN cluster c ON c.id = w.cluster_id
LEFT JOIN LATERAL (
    SELECT s2.id
    FROM sbom s2
    WHERE (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
    LIMIT 1
) s ON true
WHERE w.cluster_id = $1
  AND w.image_digest IS NOT NULL
  AND s.id IS NULL
  AND c.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
GROUP BY w.image_ref, w.image_digest
ORDER BY COUNT(*) DESC, w.image_ref ASC
LIMIT sqlc.narg('limit')::int;

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
-- Sorting is parameterised for the same reason as ListTopVulnerabilities: the
-- list is server-paginated, so reordering the rows on the current page would
-- claim a ranking the other pages do not share.
ORDER BY
    CASE @sort_by::text
        WHEN 'cvss_score'     THEN cv.cvss_score::float8
        WHEN 'workload_count' THEN k.workload_count::float8
        WHEN 'severity'       THEN (CASE cv.severity
                                        WHEN 'CRITICAL' THEN 4
                                        WHEN 'HIGH'     THEN 3
                                        WHEN 'MEDIUM'   THEN 2
                                        WHEN 'LOW'      THEN 1
                                        ELSE 0
                                    END)::float8
    END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
    CASE WHEN @sort_by::text = 'canonical_id' AND @sort_dir::text = 'asc'  THEN cv.canonical_id END ASC  NULLS LAST,
    CASE WHEN @sort_by::text = 'canonical_id' AND @sort_dir::text = 'desc' THEN cv.canonical_id END DESC NULLS LAST,
    -- Severity then CVSS remain the tiebreakers, which keeps the default
    -- ordering byte-identical to the hardcoded one this replaced.
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
