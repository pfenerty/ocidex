-- name: UpsertArtifact :one
INSERT INTO artifact (type, name, group_name, purl, cpe)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (type, name, COALESCE(group_name, ''))
DO UPDATE SET
    purl = COALESCE(EXCLUDED.purl, artifact.purl),
    cpe  = COALESCE(EXCLUDED.cpe, artifact.cpe)
RETURNING id;

-- name: GetArtifact :one
-- The nested CASE aggregates signing_status(pe.data) across every SBOM under
-- this artifact, so unlike signing_status()'s single-row ladder (mutually
-- exclusive fields on one enrichment blob), here multiple WHEN branches can
-- independently be true across different SBOMs. artifact_missing is checked
-- first deliberately: it's worst-case-first so one missing artifact among
-- many SBOMs dominates the rollup rather than being masked by a sibling
-- SBOM that still verifies. This intentionally inverts the "best status
-- wins" instinct one might expect from a rollup. See ocidex-goh.16 and
-- TestArtifactRollupSigningStatus_ArtifactMissingDominates in
-- tests/integration_test.go.
SELECT a.id, a.type, a.name, a.group_name, a.purl, a.cpe, a.created_at,
       (SELECT CASE
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'artifact_missing'
           ) THEN 'artifact_missing'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verified'
           ) THEN 'verified'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verification_failed'
           ) THEN 'verification_failed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'signed'
           ) THEN 'signed'
           ELSE 'unsigned'
       END)::text AS signing_status
FROM artifact a
WHERE a.id = $1;

-- name: ListArtifacts :many
-- Same artifact_missing-first rollup precedence as GetArtifact above — see
-- that query's comment for why this cross-SBOM ladder deliberately checks
-- worst-case first.
SELECT a.id, a.type, a.name, a.group_name, a.purl, a.cpe, a.created_at,
       COUNT(s.id) AS sbom_count,
       COUNT(s.id) FILTER (WHERE s.enrichment_sufficient) AS sufficient_sbom_count,
       (SELECT CASE
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'artifact_missing'
           ) THEN 'artifact_missing'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verified'
           ) THEN 'verified'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verification_failed'
           ) THEN 'verification_failed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND pe.status = 'success' AND signing_status(pe.data) = 'signed'
           ) THEN 'signed'
           ELSE 'unsigned'
       END)::text AS signing_status,
       -- Severity counts for this artifact's newest SBOM (ocidex-unn8.9). They
       -- come from sbom_vuln_rollup rather than an aggregate over component:
       -- ocidex-ckv.2 measured that shape at ~53s against a 30s timeout, which
       -- is why the rollups exist at all.
       --
       -- Newest SBOM, not a union across every SBOM under the artifact: a union
       -- would keep reporting the artifact vulnerable long after the fix
       -- shipped, because the fixed version does not delete its predecessors.
       -- That differs from the signing_status ladder above, which *is*
       -- worst-case-across-SBOMs — deliberately, since an unsigned sibling is a
       -- live gap while a superseded CVE is not.
       --
       -- The rollup holds a row only for an SBOM with at least one finding, so
       -- a zero total here means "no findings" *or* "never scanned" and this
       -- join cannot tell them apart (ADR-044). Coalescing to zero is safe only
       -- because that same invariant makes a zero unambiguous — it can only
       -- have come from a missing row. The service maps a zero total back to a
       -- nil summary so the UI says "not scanned"; rendering it as a clean zero
       -- is the bug.
       COALESCE(vr.critical, 0)::bigint AS vuln_critical,
       COALESCE(vr.high,     0)::bigint AS vuln_high,
       COALESCE(vr.medium,   0)::bigint AS vuln_medium,
       COALESCE(vr.low,      0)::bigint AS vuln_low,
       COALESCE(vr.unknown,  0)::bigint AS vuln_unknown
FROM artifact a
LEFT JOIN sbom s ON s.artifact_id = a.id
-- The inner join is LEFT so the lateral picks the *newest* SBOM and then looks
-- for its rollup row, rather than the newest SBOM that happens to have one:
-- an inner join would silently fall back to a superseded SBOM's findings.
LEFT JOIN LATERAL (
    SELECT COALESCE(r.critical, 0)::bigint AS critical,
           COALESCE(r.high,     0)::bigint AS high,
           COALESCE(r.medium,   0)::bigint AS medium,
           COALESCE(r.low,      0)::bigint AS low,
           COALESCE(r.unknown,  0)::bigint AS unknown,
           (COALESCE(r.critical, 0) + COALESCE(r.high, 0) + COALESCE(r.medium, 0)
            + COALESCE(r.low, 0) + COALESCE(r.unknown, 0))::bigint AS total
    FROM sbom sv
    LEFT JOIN sbom_vuln_rollup r ON r.sbom_id = sv.id
    WHERE sv.artifact_id = a.id
    ORDER BY sv.created_at DESC, sv.id DESC
    LIMIT 1
) vr ON TRUE
WHERE (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('name')::text IS NULL OR a.name ILIKE '%' || sqlc.narg('name')::text || '%')
  AND (sqlc.narg('require_sufficient')::boolean IS NULL
       OR NOT sqlc.narg('require_sufficient')::boolean
       OR EXISTS (SELECT 1 FROM sbom s2 WHERE s2.artifact_id = a.id AND s2.enrichment_sufficient))
  -- owned_only is the ownership path for /api/v1/users/me/artifacts. An
  -- artifact is "mine" when it appears in a namespace I own; artifact_visible()
  -- would additionally admit every public artifact and every artifact with no
  -- namespace link at all, which is exactly what this collection must exclude
  -- (ocidex-998g.2, and see ListNamespaces).
  AND CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
           THEN EXISTS (
               SELECT 1 FROM artifact_namespace an
               JOIN namespace n ON n.id = an.namespace_id
               WHERE an.artifact_id = a.id AND n.owner_id = sqlc.narg('user_id')::uuid)
           ELSE artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
      END
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (a.name, a.type, a.id) > (sqlc.narg('cursor_name')::text, sqlc.narg('cursor_type')::text, sqlc.narg('cursor_id')::uuid)
  )
GROUP BY a.id, vr.critical, vr.high, vr.medium, vr.low, vr.unknown, vr.total
-- Two orderings in one query. The severity keys are wrapped in a CASE that
-- collapses to NULL when @sort_severity is false, which makes every row tie on
-- them and hands the decision to the trailing (name, type, id) — the default
-- ordering, unchanged. A second query would have meant a second copy of the
-- WHERE clause above, and a filter that drifts between the two paths is a
-- worse bug than six CASEs.
--
-- Direction is a sign flip (@sort_dir is 1 for desc, -1 for asc) rather than a
-- second pair of keys, which works because counts are non-negative. The
-- zero-total gate is *outside* that flip on purpose: a zero total is unknown,
-- not clean, so it sorts last in both directions. Floating never-scanned
-- artifacts to the top of an ascending sort would present them as the safest
-- thing on the page, which is the ADR-044 mistake.
--
-- Counts are compared rank by rank rather than as one total so a single
-- critical outranks a hundred lows.
ORDER BY
    CASE WHEN @sort_severity::boolean THEN COALESCE(vr.total, 0) = 0 END,
    CASE WHEN @sort_severity::boolean THEN COALESCE(vr.critical, 0) * @sort_dir::int END DESC,
    CASE WHEN @sort_severity::boolean THEN COALESCE(vr.high,     0) * @sort_dir::int END DESC,
    CASE WHEN @sort_severity::boolean THEN COALESCE(vr.medium,   0) * @sort_dir::int END DESC,
    CASE WHEN @sort_severity::boolean THEN COALESCE(vr.low,      0) * @sort_dir::int END DESC,
    CASE WHEN @sort_severity::boolean THEN COALESCE(vr.unknown,  0) * @sort_dir::int END DESC,
    a.name, a.type, a.id
-- Offset is 0 on the keyset path; it only moves under the severity sort, where
-- ADR-043 rule (1) rules a keyset cursor out — the ORDER BY columns are a
-- rollup that a refresh pass rewrites under the reader's feet.
LIMIT @row_limit OFFSET @row_offset;

-- name: LookupArtifacts :many
-- ADR-042 R3/R4: name-keyed resolver. Unlike ListArtifacts, `name` here is an
-- exact key, not an ILIKE search — the resolver's contract is unique-or-409,
-- so a substring match would make ambiguity the normal case. `type` and
-- `group_name` are the R4 ladder rungs; NULL means wildcard, not an
-- empty-string match, so omitting a qualifier widens the query rather than
-- pinning it to rows with an empty value.
--
-- R5: artifact_visible() is applied here so the caller counts only visible
-- candidates. A private artifact must not turn a unique public match into a
-- 409 — that would leak its existence.
SELECT a.id, a.type, a.name, a.group_name
FROM artifact a
WHERE a.name = @name::text
  AND (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('group_name')::text IS NULL OR COALESCE(a.group_name, '') = sqlc.narg('group_name'))
  AND artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY a.type, a.group_name NULLS FIRST, a.id
LIMIT 50;

-- name: CountSBOMsByArtifact :one
-- Counts visible SBOMs for an artifact. Replaces the prior trick of reading
-- COUNT(*) OVER() off ListSBOMsByArtifact, which is now keyset-paginated.
SELECT COUNT(*)
FROM sbom s
WHERE s.artifact_id = $1
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean);

-- name: CountSufficientSBOMsByArtifact :one
-- Counts visible SBOMs for an artifact whose enrichment is sufficient. Kept
-- separate from CountSBOMsByArtifact rather than added to it as a second
-- column: that query's callers all want the plain total, and widening its
-- return type to a row struct would churn every one of them.
SELECT COUNT(*)
FROM sbom s
WHERE s.artifact_id = $1
  AND s.enrichment_sufficient
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean);

-- name: GetArtifactOwnerID :one
SELECT n.owner_id
FROM artifact_namespace an
JOIN namespace n ON n.id = an.namespace_id
WHERE an.artifact_id = $1 AND n.owner_id IS NOT NULL
LIMIT 1;

-- name: UpsertArtifactNamespace :exec
INSERT INTO artifact_namespace (artifact_id, namespace_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteSBOMsByArtifact :execrows
DELETE FROM sbom WHERE artifact_id = $1;

-- name: DeleteArtifact :execrows
DELETE FROM artifact WHERE id = $1;

-- name: ListSBOMsByArtifact :many
SELECT s.id, s.serial_number, s.spec_version, s.version, s.subject_version, s.digest, s.created_at,
       (SELECT COUNT(*) FROM component c WHERE c.sbom_id = s.id) AS component_count,
       (COALESCE(e.data->>'created', u.data->>'created'))::timestamptz AS build_date,
       COALESCE(e.data->>'imageVersion', u.data->>'imageVersion') AS image_version,
       COALESCE(e.data->>'architecture', u.data->>'architecture') AS architecture,
       COALESCE(e.data->>'revision', u.data->>'revision') AS revision,
       COALESCE(e.data->>'sourceUrl', u.data->>'sourceUrl') AS source_url,
       s.enrichment_sufficient,
       s.flavor
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user' AND u.status = 'success'
WHERE s.artifact_id = $1
  AND (sqlc.narg('subject_version')::text IS NULL OR s.subject_version = sqlc.narg('subject_version'))
  AND (sqlc.narg('image_version')::text IS NULL
       OR COALESCE(e.data->>'imageVersion', u.data->>'imageVersion') = sqlc.narg('image_version'))
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (s.created_at, s.id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY s.created_at DESC, s.id DESC
LIMIT @row_limit;

-- name: ListArtifactVersions :many
WITH sboms_meta AS (
    SELECT
        s.id,
        s.created_at,
        s.enrichment_sufficient,
        COALESCE(s.subject_version,
            COALESCE(e.data->>'imageVersion', u.data->>'imageVersion'),
            s.id::text)                                                  AS version_key,
        COALESCE(e.data->>'architecture', u.data->>'architecture')       AS architecture,
        COALESCE(e.data->>'imageVersion',  u.data->>'imageVersion')      AS image_version,
        COALESCE(e.data->>'revision',      u.data->>'revision')          AS revision,
        COALESCE(e.data->>'sourceUrl',     u.data->>'sourceUrl')         AS source_url,
        (COALESCE(e.data->>'created',      u.data->>'created'))::timestamptz AS build_date,
        signing_status(p.data) AS signing_status
    FROM sbom s
    LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
    LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user'         AND u.status = 'success'
    LEFT JOIN enrichment p ON p.sbom_id = s.id AND p.enricher_name = 'provenance'   AND p.status = 'success'
    WHERE s.artifact_id = $1
      AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
),
newest_per_version AS (
    SELECT DISTINCT ON (version_key)
        id, version_key, created_at, enrichment_sufficient, image_version, revision, source_url, build_date, signing_status
    FROM sboms_meta
    ORDER BY version_key, created_at DESC
),
architectures_per_version AS (
    SELECT
        version_key,
        array_agg(DISTINCT architecture) FILTER (WHERE architecture IS NOT NULL) AS architectures
    FROM sboms_meta
    GROUP BY version_key
),
sbom_count_per_version AS (
    SELECT version_key, COUNT(*) AS sbom_count
    FROM sboms_meta
    GROUP BY version_key
)
SELECT
    n.version_key,
    n.id           AS newest_sbom_id,
    n.created_at,
    n.enrichment_sufficient,
    n.image_version,
    n.revision,
    n.source_url,
    n.build_date,
    n.signing_status,
    a.architectures,
    c.sbom_count,
    -- Severity counts come from the version's newest SBOM, the same row every
    -- other column here already describes. Unioning findings across every SBOM
    -- in the version would keep reporting it vulnerable after the fix shipped.
    --
    -- sbom_vuln_rollup holds a row only for an SBOM with at least one finding,
    -- so a missing row is "no known vulnerabilities" *or* "never scanned" and
    -- this join cannot tell them apart (ADR-044). Coalescing to zero here is
    -- safe only because that same invariant makes a zero total unambiguous:
    -- it can only have come from a missing row, never from a real scan. The
    -- service maps a zero total back to a nil summary so the UI says "not
    -- scanned"; rendering it as a clean zero is the bug.
    COALESCE(r.critical, 0)::bigint AS vuln_critical,
    COALESCE(r.high,     0)::bigint AS vuln_high,
    COALESCE(r.medium,   0)::bigint AS vuln_medium,
    COALESCE(r.low,      0)::bigint AS vuln_low,
    COALESCE(r.unknown,  0)::bigint AS vuln_unknown,
    COUNT(*) OVER() AS total_count
FROM newest_per_version n
JOIN architectures_per_version a ON a.version_key = n.version_key
JOIN sbom_count_per_version c ON c.version_key = n.version_key
LEFT JOIN sbom_vuln_rollup r ON r.sbom_id = n.id
ORDER BY n.created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: CountArtifactVersions :one
SELECT COUNT(DISTINCT
    COALESCE(s.subject_version,
        COALESCE(e.data->>'imageVersion', u.data->>'imageVersion'),
        s.id::text)
)::bigint AS version_count
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user'         AND u.status = 'success'
WHERE s.artifact_id = $1
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean);
