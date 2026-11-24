-- name: GetArtifactByIdentity :one
-- Ingest's lock-free read before UpsertArtifact. An ON CONFLICT
-- DO UPDATE row-locks the artifact until the ingest commits, even when it
-- changes nothing, so concurrent ingests of one image would queue on it.
SELECT id, purl, cpe FROM artifact
WHERE type = $1 AND name = $2 AND COALESCE(group_name, '') = COALESCE(sqlc.narg('group_name')::text, '');

-- name: UpsertArtifact :one
-- The artifact row is shared by name across namespaces, so its purl and cpe are
-- only rewritten by an ingest into a namespace that already holds the artifact
-- (or when no namespace holds it). Any other namespace's ingest leaves them as
-- they are: the conflict arm updates nothing and RETURNING yields no row, which
-- the caller answers by reading the existing id.
INSERT INTO artifact (type, name, group_name, purl, cpe)
VALUES (@type, @name, sqlc.narg('group_name'), sqlc.narg('purl'), sqlc.narg('cpe'))
ON CONFLICT (type, name, COALESCE(group_name, ''))
DO UPDATE SET
    purl = COALESCE(EXCLUDED.purl, artifact.purl),
    cpe  = COALESCE(EXCLUDED.cpe, artifact.cpe)
WHERE EXISTS (
          SELECT 1 FROM artifact_namespace an
          WHERE an.artifact_id = artifact.id
            AND an.namespace_id = sqlc.narg('namespace_id')::uuid)
   OR NOT EXISTS (
          SELECT 1 FROM artifact_namespace an
          WHERE an.artifact_id = artifact.id)
RETURNING id;

-- name: GetArtifact :one
-- The nested CASE aggregates signing_status(pe.data) across every SBOM under
-- this artifact, so unlike signing_status()'s single-row ladder (mutually
-- exclusive fields on one enrichment blob), here multiple WHEN branches can
-- independently be true across different SBOMs. The order is worst-case-first
-- throughout, which intentionally inverts the "best status wins" instinct one
-- might expect from a rollup: one missing artifact, or one signature that
-- failed to verify, dominates rather than being masked by a sibling SBOM that
-- still verifies.
--
-- verification_failed sits above verified rather than below it.
-- It used to sit below, which made this ladder worst-first only at its top
-- rung: a signature that had actually been checked and rejected — the
-- strongest negative signal the provenance enricher can produce — was hidden
-- by any sibling that happened to pass.
--
-- signed sits above verified for the same reason. A signature
-- that was found but never checked is a weaker claim than one that was, and
-- with verified first an artifact whose newest builds went unchecked still
-- read "Verified" from its older siblings — while the list's tooltip promised
-- the worst status across every SBOM.
--
-- unsigned stays the ELSE: it is the absence of a claim, not a failed one.
--
-- See ocidex-goh.16 and, in tests/artifact_rollup_scope_test.go,
-- TestArtifactRollupSigningStatus_ArtifactMissingDominates and
-- TestArtifactRollupSigningStatus_FailureBeatsVerified.
SELECT a.id, a.type, a.name, a.group_name, a.purl, a.cpe, a.created_at, a.entry_number,
       (SELECT CASE
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'artifact_missing'
           ) THEN 'artifact_missing'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verification_failed'
           ) THEN 'verification_failed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'signed'
           ) THEN 'signed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verified'
           ) THEN 'verified'
           ELSE 'unsigned'
       END)::text AS signing_status
FROM artifact a
WHERE a.id = @id;

-- name: GetArtifactIDByEntryNumber :one
-- Resolves "#12" from search. artifact_visible() applies, so a private
-- artifact's number resolves to nothing for a caller who cannot see it.
SELECT a.id
FROM artifact a
WHERE a.entry_number = @entry_number::bigint
  AND artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]);

-- name: CountLatestVersionPackages :one
-- Components in the SBOM the artifact is counted from (artifact_headline_sbom).
-- Zero when nothing is visible.
SELECT COUNT(*)::bigint AS package_count
FROM component c
WHERE c.sbom_id = artifact_headline_sbom(@artifact_id::uuid, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean);

-- name: CountArtifacts :one
-- The total behind ListArtifacts' first page, under the same filters and
-- visibility rule, so the list can say "20 of 126". Keyset
-- pages carry no total of their own (ADR-043).
SELECT COUNT(*)::bigint
FROM artifact a
WHERE (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('name')::text IS NULL OR a.name ILIKE like_contains(sqlc.narg('name')::text))
  AND (sqlc.narg('require_sufficient')::boolean IS NULL
       OR NOT sqlc.narg('require_sufficient')::boolean
       OR EXISTS (SELECT 1 FROM sbom s2 WHERE s2.artifact_id = a.id AND s2.enrichment_sufficient))
  AND CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
           THEN EXISTS (
               SELECT 1 FROM artifact_namespace an
               WHERE an.artifact_id = a.id
                 AND an.namespace_id IN (
                       SELECT owned_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('key_namespaces')::uuid[])))
           ELSE artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[])
      END;

-- name: ListArtifacts :many
-- Same worst-case-first rollup precedence as GetArtifact above — see that
-- query's comment. The two ladders are duplicated rather than shared, so a
-- change to one that is not made to the other is how they drift; both are
-- asserted together in TestArtifactRollupSigningStatus_FailureBeatsVerified.
SELECT a.id, a.type, a.name, a.group_name, a.purl, a.cpe, a.created_at, a.entry_number,
       COUNT(s.id) AS sbom_count,
       COUNT(s.id) FILTER (WHERE s.enrichment_sufficient) AS sufficient_sbom_count,
       (SELECT CASE
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'artifact_missing'
           ) THEN 'artifact_missing'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verification_failed'
           ) THEN 'verification_failed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'signed'
           ) THEN 'signed'
           WHEN EXISTS (
               SELECT 1 FROM enrichment pe JOIN sbom sx ON sx.id = pe.sbom_id
               WHERE sx.artifact_id = a.id AND pe.enricher_name = 'provenance'
                 AND sx.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
                 AND pe.status = 'success' AND signing_status(pe.data) = 'verified'
           ) THEN 'verified'
           ELSE 'unsigned'
       END)::text AS signing_status,
       -- Severity counts for this artifact's latest *version*. They come from
       -- sbom_vuln_rollup rather than an aggregate over component: that shape
       -- measured ~53s against a 30s timeout, which is why the rollups exist.
       --
       -- One version, not a union across every SBOM under the artifact: a union
       -- would keep reporting the artifact vulnerable long after the fix
       -- shipped, because the fixed version does not delete its predecessors.
       -- That differs from the signing_status ladder above, which *is*
       -- worst-case-across-SBOMs — deliberately, since a signing failure
       -- anywhere is a live gap while a superseded CVE is not.
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
       COALESCE(vr.unknown,  0)::bigint AS vuln_unknown,
       COALESCE(vr.fixable,  0)::bigint AS vuln_fixable,
       -- Which SBOM those counts are from, so the row can say so.
       vr.sbom_id AS counted_sbom_id,
       vr.subject_version AS counted_version,
       COALESCE(vr.architecture, '')::text AS counted_architecture
FROM artifact a
-- An artifact is visible when any namespace it appears in is, so it can carry
-- SBOMs from a namespace the viewer cannot see. Every SBOM read below is
-- filtered to the viewer's namespaces: counting or picking one of the others
-- would leak a private version through a shared artifact.
LEFT JOIN sbom s ON s.artifact_id = a.id
    AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
-- The inner join is LEFT so the lateral picks the winning SBOM and then looks
-- for its rollup row, rather than the newest SBOM that happens to have one:
-- an inner join would silently fall back to a superseded SBOM's findings.
-- The counted SBOM is artifact_headline_sbom()'s pick, the one every artifact
-- surface shares. The rollup is LEFT-joined to it rather than searched for, so
-- a headline SBOM with no rollup row reads as no findings instead of falling
-- back to an older SBOM that has one.
LEFT JOIN LATERAL (
    SELECT h.id AS sbom_id, hs.subject_version, sbom_architecture(h.id) AS architecture,
           r.critical, r.high, r.medium, r.low, r.unknown, r.fixable,
           (r.critical + r.high + r.medium + r.low + r.unknown)::bigint AS total
    FROM (SELECT artifact_headline_sbom(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean) AS id) h
    JOIN sbom hs ON hs.id = h.id
    LEFT JOIN sbom_vuln_rollup r ON r.sbom_id = h.id
) vr ON TRUE
WHERE (sqlc.narg('type')::text IS NULL OR a.type = sqlc.narg('type'))
  AND (sqlc.narg('name')::text IS NULL OR a.name ILIKE like_contains(sqlc.narg('name')::text))
  AND (sqlc.narg('require_sufficient')::boolean IS NULL
       OR NOT sqlc.narg('require_sufficient')::boolean
       OR EXISTS (SELECT 1 FROM sbom s2 WHERE s2.artifact_id = a.id AND s2.enrichment_sufficient))
  -- owned_only is the ownership path for /api/v1/users/me/artifacts. An
  -- artifact is "mine" when it appears in a namespace I own; artifact_visible()
  -- would additionally admit every public artifact and every artifact with no
  -- namespace link at all, which is exactly what this collection must exclude
  -- (see ListNamespaces).
  AND CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
           THEN EXISTS (
               SELECT 1 FROM artifact_namespace an
               WHERE an.artifact_id = a.id
                 AND an.namespace_id IN (
                       SELECT owned_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('key_namespaces')::uuid[])))
           ELSE artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[])
      END
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (a.name, a.type, a.id) > (sqlc.narg('cursor_name')::text, sqlc.narg('cursor_type')::text, sqlc.narg('cursor_id')::uuid)
  )
GROUP BY a.id, vr.sbom_id, vr.subject_version, vr.architecture,
         vr.critical, vr.high, vr.medium, vr.low, vr.unknown, vr.fixable, vr.total
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

-- name: ListArtifactCriticalHistory :many
-- The newest versions of each listed artifact with their critical counts, for
-- the per-artifact sprite. Run for one page of artifacts at a time rather than
-- joined into ListArtifacts, which is already the heaviest list query.
--
-- One row per version: the newest SBOM of each subject_version, ordered the way
-- ListArtifacts picks its latest version. Twelve rather than six, because the
-- client keeps only the newest version's variant ("-trixie") and a variant can
-- interleave with others. `scanned` is false when the rollup has no row, which
-- is "no findings" or "never scanned" indistinguishably (ADR-044); the client
-- leaves those as gaps rather than drawing them as zero.
WITH per_version AS (
    SELECT DISTINCT ON (s.artifact_id, s.subject_version)
        s.id, s.artifact_id, s.subject_version, s.version_prerelease, s.version_variant,
        s.version_major, s.version_minor, s.version_patch, s.created_at, x.arch
    FROM sbom s
    CROSS JOIN LATERAL (SELECT sbom_architecture(s.id) AS arch) x
    WHERE s.artifact_id = ANY(@artifact_ids::uuid[])
      AND s.subject_version IS NOT NULL
      AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
    -- version_headline_sbom()'s pick within each version, inline.
    ORDER BY s.artifact_id, s.subject_version, sbom_arch_rank(x.arch), x.arch, s.created_at DESC, s.id DESC
),
-- Ranked the way artifact_headline_sbom() orders versions, so rank 1 is the
-- version the artifact is counted from.
ranked AS (
    SELECT pv.*,
           ROW_NUMBER() OVER (
               PARTITION BY pv.artifact_id
               ORDER BY pv.version_prerelease,
                        pv.version_major DESC NULLS LAST,
                        pv.version_minor DESC NULLS LAST,
                        pv.version_patch DESC NULLS LAST,
                        pv.version_variant <> '',
                        pv.version_variant,
                        pv.created_at DESC, pv.id DESC
           ) AS rn
    FROM per_version pv
)
SELECT r.artifact_id,
       r.subject_version::text AS version_key,
       r.rn::bigint AS rank,
       -- The architecture the count was taken from: the client compares two
       -- versions only when it matches.
       COALESCE(r.arch, '')::text AS architecture,
       COALESCE(vr.critical, 0)::bigint AS critical,
       (vr.sbom_id IS NOT NULL)::boolean AS scanned
FROM ranked r
LEFT JOIN sbom_vuln_rollup vr ON vr.sbom_id = r.id
WHERE r.rn <= 12
ORDER BY r.artifact_id, r.rn;

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
  AND artifact_visible(a.id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[])
ORDER BY a.type, a.group_name NULLS FIRST, a.id
LIMIT 50;

-- name: CountSBOMsByArtifact :one
-- Counts visible SBOMs for an artifact. Replaces the prior trick of reading
-- COUNT(*) OVER() off ListSBOMsByArtifact, which is now keyset-paginated.
SELECT COUNT(*)
FROM sbom s
WHERE s.artifact_id = $1
  AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]));

-- name: CountSufficientSBOMsByArtifact :one
-- Counts visible SBOMs for an artifact whose enrichment is sufficient. Kept
-- separate from CountSBOMsByArtifact rather than added to it as a second
-- column: that query's callers all want the plain total, and widening its
-- return type to a row struct would churn every one of them.
SELECT COUNT(*)
FROM sbom s
WHERE s.artifact_id = $1
  AND s.enrichment_sufficient
  AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]));

-- name: ListArtifactNamespaceIDs :many
-- Every namespace the artifact hangs from. An artifact is shared by name across
-- namespaces with different members, so an authorization check asks its
-- question of each of them rather than of whichever row happens to sort first.
SELECT an.namespace_id
FROM artifact_namespace an
WHERE an.artifact_id = $1
ORDER BY an.namespace_id;

-- name: UpsertArtifactNamespace :exec
INSERT INTO artifact_namespace (artifact_id, namespace_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteSBOMsByArtifact :execrows
DELETE FROM sbom WHERE artifact_id = $1;

-- name: DeleteArtifact :execrows
DELETE FROM artifact WHERE id = $1;

-- name: DeleteArtifactSBOMsInNamespaces :many
-- Deletes only the artifact's SBOMs that live in the given namespaces, so a
-- caller removing an artifact from their namespaces leaves every other
-- namespace's SBOMs of the same artifact in place.
DELETE FROM sbom
WHERE artifact_id = @artifact_id::uuid
  AND namespace_id = ANY (@namespace_ids::uuid[])
RETURNING id;

-- name: UnlinkArtifactNamespaces :exec
DELETE FROM artifact_namespace
WHERE artifact_id = @artifact_id::uuid
  AND namespace_id = ANY (@namespace_ids::uuid[]);

-- name: DeleteArtifactIfUnused :execrows
-- Deletes the artifact row only once no namespace holds it and no SBOM is left
-- under it.
DELETE FROM artifact a
WHERE a.id = $1
  AND NOT EXISTS (SELECT 1 FROM artifact_namespace an WHERE an.artifact_id = a.id)
  AND NOT EXISTS (SELECT 1 FROM sbom s WHERE s.artifact_id = a.id);

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
  AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (s.created_at, s.id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY s.created_at DESC, s.id DESC
LIMIT @row_limit;

-- name: ListSBOMCandidatesByArtifact :many
-- The changelog's candidate list. Deliberately not ListSBOMsByArtifact: that
-- query carries a correlated (SELECT COUNT(*) FROM component ...) per row, and
-- the changelog asks for up to 10,000 rows, so it paid for counting every
-- component of every version before paging anything. It reads
-- only these four columns -- architecture and build date come from
-- ListSBOMEnrichmentsByArtifact -- so the count and the enrichment joins were
-- pure cost here.
SELECT s.id, s.subject_version, s.created_at, s.flavor
FROM sbom s
WHERE s.artifact_id = $1
  AND (sqlc.narg('subject_version')::text IS NULL OR s.subject_version = sqlc.narg('subject_version'))
  AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
ORDER BY s.created_at DESC, s.id DESC
LIMIT @row_limit;

-- name: ListArtifactVersions :many
WITH sboms_meta AS (
    SELECT
        s.id,
        s.created_at,
        s.enrichment_sufficient,
        s.version_major, s.version_minor, s.version_patch,
        s.version_prerelease, s.version_variant,
        COALESCE(s.flavor, '') AS flavor,
        COALESCE(s.subject_version,
            COALESCE(e.data->>'imageVersion', u.data->>'imageVersion'),
            '(untagged)')                                                  AS version_key,
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
      AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]))
),
-- The SBOM each version is counted from: version_headline_sbom()'s rule (the
-- preferred architecture, then newest), applied inline because sboms_meta
-- already holds every input and calling the function per version would read
-- them again.
newest_per_version AS (
    SELECT DISTINCT ON (version_key)
        id, version_key, architecture, created_at, enrichment_sufficient, image_version, revision, source_url, build_date, signing_status,
        version_major, version_minor, version_patch, version_prerelease, version_variant, flavor
    FROM sboms_meta
    ORDER BY version_key, sbom_arch_rank(architecture), architecture, created_at DESC, id DESC
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
    COALESCE(n.architecture, '')::text AS counted_architecture,
    n.flavor::text AS flavor,
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
    COALESCE(r.fixable,  0)::bigint AS vuln_fixable,
    -- Matched against the vulnerability store long enough ago that the rollup
    -- above has caught up: two refresh intervals (RollupRefreshInterval is 15
    -- minutes). A fresher match may not be in the rollup yet, so it still reads
    -- "not scanned" rather than risk calling a version with findings clean.
    sbom_vuln_settled(n.id) AS vuln_matched,
    COUNT(*) OVER() AS total_count
FROM newest_per_version n
JOIN architectures_per_version a ON a.version_key = n.version_key
JOIN sbom_count_per_version c ON c.version_key = n.version_key
LEFT JOIN sbom_vuln_rollup r ON r.sbom_id = n.id
-- The version line's order (the service's compareVersionLine), ingest time
-- only as a tiebreak: ordering by created_at listed a version backfilled
-- later above its successor. The service re-sorts in Go; this order decides
-- which versions survive the fetch cap.
ORDER BY n.version_major DESC NULLS LAST,
         n.version_minor DESC NULLS LAST,
         n.version_patch DESC NULLS LAST,
         n.version_prerelease,
         n.version_variant <> '',
         n.version_variant,
         n.created_at DESC, n.version_key
LIMIT @row_limit OFFSET @row_offset;

-- name: CountArtifactVersions :one
SELECT COUNT(DISTINCT
    COALESCE(s.subject_version,
        COALESCE(e.data->>'imageVersion', u.data->>'imageVersion'),
        '(untagged)')
)::bigint AS version_count
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user'         AND u.status = 'success'
WHERE s.artifact_id = $1
  AND s.namespace_id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean, sqlc.narg('key_namespaces')::uuid[]));
