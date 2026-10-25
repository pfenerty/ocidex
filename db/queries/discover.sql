-- Public discovery queries (ocidex-q1z7.1).
--
-- Every query here feeds an anonymous, edge-cacheable surface, so all four are
-- scoped to PUBLIC namespaces only — and they express that scope the same way,
-- by testing namespace_id against visible_namespace_ids(NULL, false).
--
-- That call reduces to `visibility = public`, because the
-- admin term is false and nobody is a member of anything as nobody. Reusing the
-- function rather than writing `n.visibility = 'public'` inline keeps one
-- definition of visibility in the database, so a future change to the rule
-- cannot leave the discovery surface behind on the old one.
--
-- None of these take a viewer parameter, and that is deliberate. The response is
-- identical for every caller, which is what makes it cacheable at the edge; it
-- also means there is no code path by which a viewer's own private data could
-- widen an aggregate that anonymous visitors read back.
--
-- The aggregates are expensive by nature (they rank the whole public catalog).
-- They are computed by the stats warmer out of band, never on a request path.

-- name: GetDiscoverTopArtifacts :many
-- Artifacts ranked by discovery_score: usage breadth, version breadth, recency.
--
-- usage_count is the ADR-041 "usages" relation counted rather than listed: how
-- many *other* artifacts' latest public SBOM contains a component matching
-- this artifact. That is the figure the Relationships tab reports ("ships in N
-- artifacts"), and it has to be: counting SBOMs instead, and leaving out the
-- ADR-048 R6 command branch, ranked every ocidex command artifact at "0 uses"
-- while its Relationships tab named the image that ships it (ocidex-nps9.5).
--
-- The match is the same coarse one ListArtifactUsages does: purl base via
-- idx_component_purl_base, the (type, name, group) tuple for purl-less rows,
-- and for a golang purl the module component of a binary whose file name is
-- this artifact's name (R6). It is a superset for the same reason: identity
-- qualifiers are settled in Go by componentKey(). A count does not need that
-- exactness, so the Go pass is skipped rather than pulling every matching
-- component row into the service to be filtered and thrown away.
--
-- The match branches are separate CTEs unioned, not one predicate with OR.
-- An OR across two relations cannot be planned as a hash join, so the combined
-- form degrades to a nested loop over the component table; split, each branch is
-- a clean join against its own index.
WITH public_ns AS (
    SELECT visible_namespace_ids(NULL::uuid, false) AS id
),
public_sbom AS (
    SELECT s.id, s.artifact_id, s.subject_version, s.created_at
    FROM sbom s
    WHERE s.namespace_id IN (SELECT id FROM public_ns)
),
public_latest AS (
    -- Each consumer's newest public SBOM, the one the Relationships tab reads.
    SELECT DISTINCT ON (ps.artifact_id) ps.id, ps.artifact_id
    FROM public_sbom ps
    ORDER BY ps.artifact_id, ps.created_at DESC, ps.id DESC
),
subject AS (
    -- Only artifacts with at least one public SBOM are candidates: the JOIN is
    -- inner, so an artifact whose SBOMs are all private is not merely scored
    -- zero, it is absent.
    SELECT a.id,
           a.type,
           a.name,
           a.group_name,
           a.purl,
           CASE WHEN a.purl IS NULL THEN NULL
                ELSE split_part(split_part(a.purl, '?', 1), '@', 1)
           END                                                   AS purl_base,
           COUNT(DISTINCT COALESCE(ps.subject_version, ''))::bigint AS version_count,
           COUNT(DISTINCT ps.id)::bigint                         AS sbom_count,
           MAX(ps.created_at)::timestamptz                       AS last_seen_at
    FROM artifact a
    JOIN public_sbom ps ON ps.artifact_id = a.id
    GROUP BY a.id, a.type, a.name, a.group_name, a.purl
),
usage_purl AS (
    SELECT sub.id AS artifact_id, pl.artifact_id AS consumer_id
    FROM subject sub
    JOIN component c
      ON c.purl IS NOT NULL
     AND split_part(split_part(c.purl, '?', 1), '@', 1) = sub.purl_base
    JOIN public_latest pl ON pl.id = c.sbom_id AND pl.artifact_id <> sub.id
    WHERE sub.purl_base IS NOT NULL
),
usage_tuple AS (
    SELECT sub.id AS artifact_id, pl.artifact_id AS consumer_id
    FROM subject sub
    JOIN component c
      ON c.purl IS NULL
     AND c.type = sub.type
     AND c.name = sub.name
     AND COALESCE(c.group_name, '') = COALESCE(sub.group_name, '')
    JOIN public_latest pl ON pl.id = c.sbom_id AND pl.artifact_id <> sub.id
    WHERE sub.purl_base IS NULL
),
module_base AS (
    -- Every path-boundary prefix of a golang purl base below the full path,
    -- as modulePurlBases() builds them in Go: equality against these is what
    -- the purl-base index serves.
    SELECT sub.id AS artifact_id, sub.name,
           array_to_string((string_to_array(sub.purl_base, '/'))[1:n], '/') AS base
    FROM subject sub
    CROSS JOIN LATERAL generate_series(2, cardinality(string_to_array(sub.purl_base, '/')) - 1) AS n
    WHERE sub.purl_base LIKE 'pkg:golang/%'
),
usage_command AS (
    SELECT mb.artifact_id, pl.artifact_id AS consumer_id
    FROM module_base mb
    JOIN component c
      ON c.purl IS NOT NULL
     AND c.file_path IS NOT NULL
     AND split_part(split_part(c.purl, '?', 1), '@', 1) = mb.base
     AND regexp_replace(c.file_path, '^.*/', '') = mb.name
    JOIN public_latest pl ON pl.id = c.sbom_id AND pl.artifact_id <> mb.artifact_id
),
usage AS (
    SELECT m.artifact_id, COUNT(DISTINCT m.consumer_id)::bigint AS usage_count
    FROM (
        SELECT artifact_id, consumer_id FROM usage_purl
        UNION ALL
        SELECT artifact_id, consumer_id FROM usage_tuple
        UNION ALL
        SELECT artifact_id, consumer_id FROM usage_command
    ) m
    GROUP BY m.artifact_id
)
SELECT sub.id                                AS artifact_id,
       sub.type,
       sub.name,
       sub.group_name,
       sub.purl,
       COALESCE(u.usage_count, 0)::bigint    AS usage_count,
       sub.version_count,
       sub.sbom_count,
       sub.last_seen_at,
       discovery_score(COALESCE(u.usage_count, 0), sub.version_count, sub.last_seen_at)::float8 AS score
FROM subject sub
LEFT JOIN usage u ON u.artifact_id = sub.id
ORDER BY score DESC, sub.name, sub.id
LIMIT @row_limit::int;

-- name: GetDiscoverRecentArtifacts :many
-- Most recently updated public artifacts, one row per artifact.
--
-- DISTINCT ON collapses to the newest SBOM per artifact, which forces its ORDER
-- BY to lead with artifact_id; the outer select restores the ordering the page
-- actually wants. Without the collapse, a single artifact re-scanned hourly
-- would fill the whole list and the panel would report activity rather than
-- breadth.
WITH latest AS (
    SELECT DISTINCT ON (s.artifact_id)
           a.id   AS artifact_id,
           a.type,
           a.name,
           a.group_name,
           s.id   AS sbom_id,
           s.subject_version,
           s.digest,
           s.flavor,
           s.created_at
    FROM sbom s
    JOIN artifact a ON a.id = s.artifact_id
    WHERE s.namespace_id IN (SELECT visible_namespace_ids(NULL::uuid, false))
    ORDER BY s.artifact_id, s.created_at DESC, s.id DESC
)
SELECT artifact_id, type, name, group_name, sbom_id, subject_version, digest, flavor, created_at
FROM latest
ORDER BY created_at DESC, artifact_id
LIMIT @row_limit::int;

-- name: GetDiscoverTopVulnerabilities :many
-- Vulnerabilities ranked by blast radius across public content.
--
-- Two stages on purpose. Stage one ranks candidates from vuln_rollup, which is
-- pre-aggregated per (canonical_id, namespace) and cheap; stage two computes the
-- affected *artifact* count, which needs the purl -> component -> sbom join that
-- ocidex-ckv.2 removed from the request path, and runs it only for the handful
-- of candidates that survived. Artifact count is the honest headline for a
-- discovery page — "affects 14 public images" is a claim a visitor can act on,
-- where an SBOM count double-counts every rescan of the same image — but it is
-- not worth a full join over 10.9M component rows to rank the whole catalog by.
--
-- The ordinality filter on the unnest is the vuln_rollup idiom from
-- ListTopVulnerabilities: unnesting purls multiplies the rows SUM would see, so
-- each rollup row is charged exactly once.
WITH public_ns AS (
    SELECT visible_namespace_ids(NULL::uuid, false) AS id
),
canonical AS (
    -- Collapse aliased OSV records (GO-xxxx + GHSA-yyyy) to one row per
    -- real-world vulnerability, preferring the alias that carries a severity.
    SELECT DISTINCT ON (canonical_id)
           id, canonical_id, severity, cvss_score, summary, published_at
    FROM vulnerability
    WHERE canonical_id <> ''
    ORDER BY canonical_id,
             CASE WHEN severity IS NOT NULL AND severity NOT IN ('UNKNOWN') THEN 0 ELSE 1 END,
             modified_at DESC NULLS LAST
),
candidate AS (
    SELECT vr.canonical_id,
           COALESCE(SUM(vr.sbom_count) FILTER (WHERE COALESCE(p.ord, 1) = 1), 0)::bigint AS affected_sbom_count,
           COALESCE(array_agg(DISTINCT p.purl) FILTER (WHERE p.purl IS NOT NULL), '{}')::text[] AS purls
    FROM vuln_rollup vr
    LEFT JOIN LATERAL unnest(vr.purls) WITH ORDINALITY AS p(purl, ord) ON true
    WHERE vr.namespace_id IN (SELECT id FROM public_ns)
    GROUP BY vr.canonical_id
    ORDER BY affected_sbom_count DESC, vr.canonical_id
    LIMIT @candidate_limit::int
)
SELECT v.id,
       v.canonical_id,
       v.severity,
       v.cvss_score,
       v.summary,
       v.published_at,
       cd.affected_sbom_count,
       ar.affected_artifact_count
FROM candidate cd
JOIN canonical v ON v.canonical_id = cd.canonical_id
CROSS JOIN LATERAL (
    SELECT COUNT(DISTINCT s.artifact_id)::bigint AS affected_artifact_count
    FROM component c
    JOIN sbom s ON s.id = c.sbom_id
    WHERE c.purl = ANY (cd.purls)
      AND s.namespace_id IN (SELECT id FROM public_ns)
) ar
ORDER BY ar.affected_artifact_count DESC,
         CASE v.severity
             WHEN 'CRITICAL' THEN 4
             WHEN 'HIGH'     THEN 3
             WHEN 'MEDIUM'   THEN 2
             WHEN 'LOW'      THEN 1
             ELSE 0
         END DESC,
         v.cvss_score DESC NULLS LAST,
         v.canonical_id
LIMIT @row_limit::int;

-- name: GetDiscoverLicenseSpread :many
-- License distribution across public content, by distinct package identity.
--
-- Inner JOIN, unlike ListLicenses' LEFT JOIN: that list is a catalog of every
-- license OCIDex knows and must show one with a zero count, whereas this is a
-- distribution, and a zero-weight slice describes nothing.
SELECT l.id,
       l.spdx_id,
       l.name,
       license_category(l.spdx_id)             AS category,
       COUNT(DISTINCT lr.identity_key)::bigint AS component_count
FROM license l
JOIN license_rollup lr
  ON lr.license_id = l.id
 AND lr.namespace_id IN (SELECT visible_namespace_ids(NULL::uuid, false))
GROUP BY l.id, l.spdx_id, l.name
ORDER BY component_count DESC, l.name
LIMIT @row_limit::int;
