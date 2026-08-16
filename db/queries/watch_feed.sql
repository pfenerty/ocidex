-- Watched-artifact change feed (ocidex-998g.4).
--
-- Three signals already exist in the schema and none of them are recomputed
-- here: a new version is a `sbom` row, a drift event is a
-- `provenance_drift_events` row, and a vulnerability finding is the same
-- component→package_vulnerability→vulnerability join the SBOM and artifact
-- vuln panels use. This query only scopes those to the caller's watch set and
-- merges them onto one timeline.
--
-- Visibility IS re-checked here, which is the deliberate opposite of
-- ListArtifactWatches. A watch row is the user's own bookmark and survives its
-- artifact going private; the *events* are content, and content the caller can
-- no longer see must not keep streaming into their feed. So a since-privatised
-- artifact stays on the watchlist and drops out of the feed.

-- name: ListWatchedArtifactEvents :many
-- Keyset on (occurred_at DESC, event_id DESC) per ADR-043 rule 2 — every branch
-- appends at the head of an ordering that does not reshuffle underneath it.
--
-- Each branch applies the cursor and takes row_limit rows before the merge, so
-- one noisy artifact cannot make the union arbitrarily large; the outer LIMIT
-- then takes the globally newest row_limit of those. The caller passes
-- row_limit+1 to detect whether a further page exists.
WITH watched AS (
    SELECT w.artifact_id, a.name AS artifact_name, a.type AS artifact_type
    FROM artifact_watch w
    JOIN artifact a ON a.id = w.artifact_id
    WHERE w.user_id = sqlc.arg('watcher_id')::uuid
),
-- The single visibility gate. Everything downstream reads from here, so no
-- branch can accidentally bypass it.
visible_sbom AS (
    SELECT s.id, s.artifact_id, s.subject_version, s.created_at,
           w.artifact_name, w.artifact_type
    FROM sbom s
    JOIN watched w ON w.artifact_id = s.artifact_id
    WHERE s.namespace_id IN (
        SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
    )
),
version_events AS (
    SELECT
        'new_version'::text AS kind,
        vs.id AS event_id,
        vs.created_at AS occurred_at,
        vs.artifact_id,
        vs.artifact_name,
        vs.artifact_type,
        vs.id AS sbom_id,
        vs.subject_version,
        -- The version this one succeeded, so the UI can deep-link straight to
        -- the existing changelog endpoint instead of restating what changed.
        -- COALESCE to '' rather than leaving it NULL: sqlc reads the cast as
        -- non-null, and '' already means exactly what NULL would here — there is
        -- no predecessor to link from, either because this is the artifact's
        -- first version or because that version carries no subject_version.
        COALESCE(LAG(vs.subject_version) OVER (
            PARTITION BY vs.artifact_id ORDER BY vs.created_at, vs.id
        ), '')::text AS previous_version,
        NULL::text AS previous_status,
        NULL::text AS new_status,
        NULL::text AS reason,
        NULL::text AS vuln_id,
        NULL::text AS vuln_severity,
        NULL::real AS vuln_cvss_score,
        NULL::text AS vuln_summary
    FROM visible_sbom vs
),
drift_events AS (
    SELECT
        'drift'::text AS kind,
        d.id AS event_id,
        d.detected_at AS occurred_at,
        vs.artifact_id,
        vs.artifact_name,
        vs.artifact_type,
        vs.id AS sbom_id,
        vs.subject_version,
        -- '' rather than NULL: sqlc types every UNION column from the first
        -- branch, where previous_version is non-null, so a NULL here would fail
        -- to scan. '' is already this query's "no predecessor" value.
        ''::text AS previous_version,
        d.previous_status,
        d.new_status,
        d.reason,
        NULL::text AS vuln_id,
        NULL::text AS vuln_severity,
        NULL::real AS vuln_cvss_score,
        NULL::text AS vuln_summary
    FROM provenance_drift_events d
    JOIN visible_sbom vs ON vs.id = d.sbom_id
),
-- Vulnerabilities are reported against the newest visible SBOM only. Fanning
-- out over every version would re-emit the same CVE once per tag for no new
-- information.
latest_sbom AS (
    SELECT DISTINCT ON (vs.artifact_id)
        vs.id, vs.artifact_id, vs.subject_version, vs.created_at,
        vs.artifact_name, vs.artifact_type
    FROM visible_sbom vs
    ORDER BY vs.artifact_id, vs.created_at DESC, vs.id DESC
),
vuln_events AS (
    SELECT
        'vulnerability'::text AS kind,
        -- vulnerability.id is text, not a uuid, and the feed cursor is
        -- (timestamptz, uuid) like every other keyset feed here. Hashing the
        -- pair that identifies the event gives a stable, unique uuid without
        -- widening the cursor for one branch.
        md5(v.canonical_id || ls.artifact_id::text)::uuid AS event_id,
        -- "Newly affecting" is whichever happened later: the advisory being
        -- published, or this artifact coming into existence. package_vulnerability
        -- has no usable first-seen column — the refresh loop delete-then-inserts
        -- every purl each cycle, so its updated_at would re-float the whole
        -- backlog to the top of the feed on every refresh.
        GREATEST(v.published_at, ls.created_at) AS occurred_at,
        ls.artifact_id,
        ls.artifact_name,
        ls.artifact_type,
        ls.id AS sbom_id,
        ls.subject_version,
        ''::text AS previous_version,
        NULL::text AS previous_status,
        NULL::text AS new_status,
        NULL::text AS reason,
        v.canonical_id AS vuln_id,
        v.severity AS vuln_severity,
        v.cvss_score AS vuln_cvss_score,
        v.summary AS vuln_summary
    FROM latest_sbom ls
    JOIN (SELECT DISTINCT sbom_id, purl FROM component WHERE purl IS NOT NULL) c
        ON c.sbom_id = ls.id
    JOIN package_vulnerability pv ON pv.purl = c.purl
    JOIN vulnerability v ON v.id = pv.vulnerability_id
    -- One row per (artifact, canonical vuln): the same advisory usually matches
    -- several purls in one image, and aliased OSV records collapse onto one
    -- canonical_id (same rule as GetArtifactVulnSummary).
    GROUP BY v.canonical_id, ls.artifact_id, ls.artifact_name, ls.artifact_type,
             ls.id, ls.subject_version, ls.created_at, v.published_at,
             v.severity, v.cvss_score, v.summary
),
merged AS (
    (SELECT * FROM version_events
     WHERE NOT sqlc.narg('has_cursor')::boolean
        OR (occurred_at, event_id) < (sqlc.narg('cursor_occurred_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
     ORDER BY occurred_at DESC, event_id DESC
     LIMIT @row_limit)
    UNION ALL
    (SELECT * FROM drift_events
     WHERE NOT sqlc.narg('has_cursor')::boolean
        OR (occurred_at, event_id) < (sqlc.narg('cursor_occurred_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
     ORDER BY occurred_at DESC, event_id DESC
     LIMIT @row_limit)
    UNION ALL
    (SELECT * FROM vuln_events
     WHERE NOT sqlc.narg('has_cursor')::boolean
        OR (occurred_at, event_id) < (sqlc.narg('cursor_occurred_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
     ORDER BY occurred_at DESC, event_id DESC
     LIMIT @row_limit)
)
SELECT * FROM merged
ORDER BY occurred_at DESC, event_id DESC
LIMIT @row_limit;
