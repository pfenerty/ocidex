-- Upgrade computation for /users/me/moves: what the caller runs, the tags it
-- could move to, and the criticals that remain once it has.

-- name: CountMyClusters :one
-- Whether the caller has a cluster to read running images from. With none the
-- report falls back to each owned artifact's newest tag.
SELECT COUNT(*)::bigint
FROM cluster c
WHERE c.namespace_id IN (SELECT owned_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('key_namespaces')::uuid[]));

-- name: ListMyRunningImages :many
-- Running images in the caller's clusters, one row per (Kubernetes namespace,
-- matched SBOM), with the pods carrying it. The SBOM is matched by digest the
-- way ListClusterImages matches it. A digest with no SBOM has nothing to
-- compute an upgrade from, so it is left out here and reported by the
-- cluster's unknown-images list instead.
WITH w AS (
    SELECT w.k8s_namespace,
           w.image_digest,
           c.namespace_id AS cluster_namespace_id,
           SUM(w.pod_count)::bigint AS pod_count
    FROM cluster_workload w
    JOIN cluster c ON c.id = w.cluster_id
    WHERE c.namespace_id IN (SELECT owned_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('key_namespaces')::uuid[]))
      AND w.image_digest IS NOT NULL
    GROUP BY w.k8s_namespace, w.image_digest, c.namespace_id
)
SELECT w.k8s_namespace::text AS k8s_namespace,
       SUM(w.pod_count)::bigint AS pod_count,
       s.id          AS sbom_id,
       s.artifact_id AS artifact_id,
       a.name        AS artifact_name
FROM w
CROSS JOIN LATERAL (
    SELECT s2.id, s2.artifact_id
    FROM sbom s2
    WHERE (s2.digest = w.image_digest OR s2.index_digest = w.image_digest)
      AND s2.namespace_id IN (SELECT cluster_sbom_namespace_ids(w.cluster_namespace_id))
    ORDER BY (s2.namespace_id = w.cluster_namespace_id) DESC, (s2.digest = w.image_digest) DESC, s2.created_at DESC
    LIMIT 1
) s
JOIN artifact a ON a.id = s.artifact_id
GROUP BY w.k8s_namespace, s.id, s.artifact_id, a.name;

-- name: ListMyOwnedHeadlines :many
-- Without a cluster, each artifact stands in as running at its newest tag in a
-- namespace the caller owns, ordered the way artifact_headline_sbom orders
-- versions, and the OCIDex namespace takes the place of the Kubernetes one.
-- Newer tags elsewhere (an upstream registry scanned into a public namespace)
-- are then the upgrades. artifact_headline_sbom itself would pick from every
-- visible namespace, so it would already be the newest and nothing could beat it.
SELECT DISTINCT ON (a.id)
       a.id   AS artifact_id,
       a.name AS artifact_name,
       s.id   AS sbom_id,
       n.name AS namespace_name
FROM artifact a
JOIN sbom s ON s.artifact_id = a.id
JOIN namespace n ON n.id = s.namespace_id
WHERE s.namespace_id IN (SELECT owned_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('key_namespaces')::uuid[]))
ORDER BY a.id,
         s.version_prerelease,
         s.version_major DESC NULLS LAST,
         s.version_minor DESC NULLS LAST,
         s.version_patch DESC NULLS LAST,
         s.version_variant <> '',
         s.version_variant,
         sbom_arch_rank(sbom_architecture(s.id)),
         s.created_at DESC, s.id DESC;

-- name: ListUpgradeCandidates :many
-- Every SBOM of the given artifacts the caller can see, plus the running SBOMs
-- themselves (a running image is the caller's to know about even when it was
-- matched from a namespace they cannot list), with what the upgrade choice
-- needs: version parts, flavor, architecture, build date and the rollup's
-- critical and high counts. settled says the counts can be trusted: an
-- unmatched SBOM has no rollup row and would read as clean.
SELECT s.id,
       s.artifact_id,
       COALESCE(s.subject_version, '')::text AS subject_version,
       COALESCE(s.flavor, '')::text          AS flavor,
       s.version_major,
       s.version_minor,
       s.version_patch,
       s.version_prerelease,
       s.version_variant,
       s.created_at,
       COALESCE(sbom_architecture(s.id), '')::text AS architecture,
       COALESCE(
         (SELECT e.data->>'created' FROM enrichment e
           WHERE e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'),
         (SELECT e.data->>'created' FROM enrichment e
           WHERE e.sbom_id = s.id AND e.enricher_name = 'user' AND e.status = 'success'),
         '')::text AS build_date,
       COALESCE(r.critical, 0)::bigint AS critical,
       COALESCE(r.high, 0)::bigint     AS high,
       sbom_vuln_settled(s.id)         AS settled
FROM sbom s
LEFT JOIN sbom_vuln_rollup r ON r.sbom_id = s.id
WHERE s.artifact_id = ANY (@artifact_ids::uuid[])
  AND (s.id = ANY (@running_ids::uuid[])
       OR s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, false, sqlc.narg('key_namespaces')::uuid[])));

-- name: ListCriticalFindings :many
-- Critical findings per SBOM, one row per (SBOM, canonical vulnerability),
-- matched like sbom_vuln_rollup counts them (purl and source purl, per Go
-- symbol set; an alias graded CRITICAL makes the finding critical). The
-- package is the first affected component by name; the fix is the first
-- fixed version any match carries, else its fix state.
WITH scope AS (
    SELECT DISTINCT c1.sbom_id, c1.name, c1.version, c1.purl::text AS match_purl, COALESCE(c1.go_symbol_set_id, 0) AS go_symbol_set_id
    FROM component c1 WHERE c1.sbom_id = ANY (@sbom_ids::uuid[]) AND c1.purl IS NOT NULL
    UNION
    SELECT DISTINCT c2.sbom_id, c2.name, c2.version, c2.source_purl::text AS match_purl, 0::bigint AS go_symbol_set_id
    FROM component c2 WHERE c2.sbom_id = ANY (@sbom_ids::uuid[]) AND c2.source_purl IS NOT NULL
)
SELECT s.sbom_id,
       COALESCE(NULLIF(v.canonical_id, ''), v.id)::text AS canonical_id,
       -- -1 when no alias carries a score; sqlc cannot type a nullable aggregate.
       COALESCE(MAX(v.cvss_score), -1)::real AS cvss_score,
       (array_agg(s.name ORDER BY s.name, s.version NULLS LAST))[1]::text AS package_name,
       COALESCE((array_agg(s.version ORDER BY s.name, s.version NULLS LAST))[1], '')::text AS package_version,
       COALESCE((array_agg(pv.fixed_version ORDER BY pv.fixed_version IS NULL, pv.fixed_version))[1], '')::text AS fixed_version,
       COALESCE((array_agg(pv.fix_state ORDER BY pv.fix_state IS NULL, pv.fix_state))[1], '')::text AS fix_state
FROM scope s
JOIN package_vulnerability pv ON pv.purl = s.match_purl AND pv.go_symbol_set_id = s.go_symbol_set_id
JOIN vulnerability v ON v.id = pv.vulnerability_id
WHERE v.severity = 'CRITICAL'
GROUP BY s.sbom_id, COALESCE(NULLIF(v.canonical_id, ''), v.id);
