-- Artifact relationship queries (ADR-041).
--
-- Relationships are DERIVED here, not stored. Both queries do a COARSE match in
-- SQL and leave the EXACT match to componentKey() in Go — see ADR-041 R1 and the
-- indexing caveat. The SQL side matches on the purl base
-- (split_part(split_part(purl,'?',1),'@',1), backed by idx_component_purl_base)
-- or, for purl-less rows, the (type, name, group) tuple. Identity qualifiers are
-- neither filtered nor sorted here, so these results are a superset; the service
-- narrows them with the same key function diff uses.
--
-- ADR-048 R6 adds a third coarse branch, for a Go command whose artifact purl
-- sits under the module purl a scanner records. On the usages side the caller
-- passes every path-boundary prefix of its own purl base as an array, so the
-- branch is still an equality lookup the purl-base index can serve; on the
-- contains side both inputs are small (one SBOM's components against the
-- artifact table) and the prefix test is written out directly. Either way the
-- binary-path check that makes the match exact is in Go, beside componentKey.
--
-- '?' is split before '@' to mirror normalizeComponentPurl(): qualifiers follow
-- the version in purl format, so a component with qualifiers and no version
-- (pkg:golang/foo?arch=amd64) would otherwise keep its qualifiers in the base.
--
-- Both directions define "latest SBOM" the same way ListSBOMsByArtifact orders:
-- created_at DESC, id DESC, restricted to SBOMs the caller can see. The
-- visibility predicate is inside the latest-SBOM subquery as well as outside it,
-- so a caller never resolves a relationship against an SBOM they cannot read —
-- and never sees "no relationship" merely because someone else's newer SBOM is
-- shadowing a visible one.

-- name: GetArtifactCurrentVersion :one
-- subject_version of the artifact's latest visible SBOM. Used to answer "is the
-- version shipped here the current one?" without a second round-trip per usage.
SELECT s.subject_version
FROM sbom s
WHERE s.artifact_id = @artifact_id
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY s.created_at DESC, s.id DESC
LIMIT 1;

-- name: ListArtifactUsages :many
-- "Where does this ship?" — artifacts whose latest visible SBOM contains a
-- component matching the subject artifact (ADR-041 R5).
--
-- Leads with the component predicate rather than the SBOM set: component is the
-- large table, and the purl-base expression index makes that the selective step.
-- The latest-SBOM test is then a correlated lookup on idx_sbom_artifact_id per
-- surviving row, not a DISTINCT ON over every SBOM in the database.
--
-- purl_base NULL selects the Rule 2 branch. It is not merely "the subject has no
-- purl": a purl-keyed subject can only match purl-keyed components and a
-- tuple-keyed subject only tuple-keyed ones, because componentKey() picks its
-- branch per row. Mixed pairs are non-matches by construction, so the two
-- branches are exclusive here too.
SELECT a.id           AS artifact_id,
       a.type         AS artifact_type,
       a.name         AS artifact_name,
       a.group_name   AS artifact_group,
       a.purl         AS artifact_purl,
       s.id           AS sbom_id,
       s.subject_version,
       s.digest,
       s.flavor,
       s.created_at,
       c.type         AS matched_type,
       c.name         AS matched_name,
       c.group_name   AS matched_group,
       c.version      AS matched_version,
       c.purl         AS matched_purl,
       c.file_path    AS matched_file_path
FROM component c
JOIN sbom s ON s.id = c.sbom_id
JOIN artifact a ON a.id = s.artifact_id
WHERE (
        (sqlc.narg('purl_base')::text IS NOT NULL
         AND c.purl IS NOT NULL
         AND split_part(split_part(c.purl, '?', 1), '@', 1) = sqlc.narg('purl_base')::text)
     OR (sqlc.narg('purl_base')::text IS NULL
         AND c.purl IS NULL
         AND c.type = @subject_type
         AND c.name = @subject_name
         AND COALESCE(c.group_name, '') = @subject_group)
     OR (cardinality(@module_purl_bases::text[]) > 0
         AND c.purl IS NOT NULL
         AND c.file_path IS NOT NULL
         AND split_part(split_part(c.purl, '?', 1), '@', 1) = ANY(@module_purl_bases::text[]))
      )
  AND s.artifact_id <> @artifact_id
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  AND s.id = (
      SELECT s2.id FROM sbom s2
      WHERE s2.artifact_id = s.artifact_id
        AND sbom_visible(s2.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
      ORDER BY s2.created_at DESC, s2.id DESC
      LIMIT 1
  )
ORDER BY a.name, a.type, a.id
LIMIT @row_limit;

-- name: ListArtifactContains :many
-- "What of ours does this carry?" — tracked artifacts matched by components of
-- the subject artifact's latest visible SBOM (ADR-041 R5). The inverse of
-- ListArtifactUsages, and the join condition is the same coarse match read from
-- the other side.
--
-- The LATERAL supplies each matched artifact's own current version/digest/flavor
-- so the caller can report drift (ADR-041 R2) without an N+1. LEFT JOIN, not
-- inner: an artifact whose SBOMs are all invisible to this caller is already
-- excluded by artifact_visible below, but an artifact row with no SBOM at all is
-- a legitimate (if unusual) match and should not vanish silently.
WITH subject_latest AS (
    SELECT s.id
    FROM sbom s
    WHERE s.artifact_id = @artifact_id
      AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
    ORDER BY s.created_at DESC, s.id DESC
    LIMIT 1
)
SELECT a.id           AS artifact_id,
       a.type         AS artifact_type,
       a.name         AS artifact_name,
       a.group_name   AS artifact_group,
       a.purl         AS artifact_purl,
       c.type         AS matched_type,
       c.name         AS matched_name,
       c.group_name   AS matched_group,
       c.version      AS matched_version,
       c.purl         AS matched_purl,
       c.file_path    AS matched_file_path,
       ls.subject_version AS current_version,
       ls.digest          AS current_digest,
       ls.flavor          AS current_flavor,
       ls.id              AS current_sbom_id
FROM component c
JOIN artifact a ON (
        (c.purl IS NOT NULL AND a.purl IS NOT NULL
         AND split_part(split_part(c.purl, '?', 1), '@', 1)
           = split_part(split_part(a.purl, '?', 1), '@', 1))
     OR (c.purl IS NULL AND a.purl IS NULL
         AND a.type = c.type
         AND a.name = c.name
         AND COALESCE(a.group_name, '') = COALESCE(c.group_name, ''))
     OR (c.purl IS NOT NULL AND a.purl IS NOT NULL
         AND c.file_path IS NOT NULL
         AND starts_with(split_part(split_part(a.purl, '?', 1), '@', 1),
                         split_part(split_part(c.purl, '?', 1), '@', 1) || '/'))
)
LEFT JOIN LATERAL (
    SELECT s2.id, s2.subject_version, s2.digest, s2.flavor
    FROM sbom s2
    WHERE s2.artifact_id = a.id
      AND sbom_visible(s2.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
    ORDER BY s2.created_at DESC, s2.id DESC
    LIMIT 1
) ls ON true
WHERE c.sbom_id = (SELECT id FROM subject_latest)
  AND a.id <> @artifact_id
  AND artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY a.name, a.type, a.id
LIMIT @row_limit;
