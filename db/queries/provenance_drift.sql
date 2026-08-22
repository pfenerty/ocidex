-- name: InsertProvenanceDrift :exec
INSERT INTO provenance_drift_events (sbom_id, previous_status, new_status, reason, previous_data, new_data)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetLatestProvenanceDrift :one
SELECT id, sbom_id, previous_status, new_status, reason, previous_data, new_data, detected_at
FROM provenance_drift_events
WHERE sbom_id = $1
ORDER BY detected_at DESC
LIMIT 1;

-- name: ListProvenanceDriftBySBOM :many
-- Keyset pagination on (detected_at DESC, id DESC). Drift events are appended
-- at the head of this ordering as re-verification runs, so OFFSET would shift
-- rows across page boundaries mid-scroll (ADR-043). The caller fetches
-- row_limit+1 to detect whether a further page exists.
SELECT id, sbom_id, previous_status, new_status, reason, detected_at
FROM provenance_drift_events
WHERE sbom_id = @sbom_id
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (detected_at, id) < (sqlc.narg('cursor_detected_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY detected_at DESC, id DESC
LIMIT @row_limit;

-- name: ListRecentProvenanceDrift :many
-- Cross-registry drift feed, keyset-paginated on (detected_at DESC, id DESC)
-- for the same reason as ListProvenanceDriftBySBOM (ADR-043). Scoped to the
-- caller's visible namespaces: an admin passing is_admin sees every tenant, a
-- namespace owner sees drift on their own (and public) artifacts only.
--
-- owned_only switches to the ownership path for the /dashboard "drift on my
-- artifacts" panel (ocidex-998g.5). It is strictly narrower than the default:
-- it drops others' public artifacts, and it ignores is_admin, because "mine"
-- means mine even for an admin. Same switch, same wording, as namespace.sql.
SELECT
    d.id, d.sbom_id, d.previous_status, d.new_status, d.reason, d.detected_at,
    s.source_id, s.artifact_id,
    a.name AS artifact_name, a.type AS artifact_type,
    src.name AS source_name
FROM provenance_drift_events d
JOIN sbom s ON s.id = d.sbom_id
LEFT JOIN artifact a ON a.id = s.artifact_id
LEFT JOIN source src ON src.id = s.source_id
WHERE (
    NOT sqlc.narg('has_cursor')::boolean
    OR (d.detected_at, d.id) < (sqlc.narg('cursor_detected_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
  AND (
    CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
         THEN s.namespace_id IN (
              SELECT id FROM namespace WHERE owner_id = sqlc.narg('user_id')::uuid)
         ELSE s.namespace_id IN (
              SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    END
  )
ORDER BY d.detected_at DESC, d.id DESC
LIMIT @row_limit;

-- UpsertProvenanceDriftPending records an unconfirmed signing-status
-- transition, replacing any prior pending observation for the same SBOM.
-- See db/migrations/00062_provenance_drift_pending.sql for why "unsigned"
-- needs a second observation before it becomes an event.
-- name: UpsertProvenanceDriftPending :exec
INSERT INTO provenance_drift_pending (sbom_id, previous_status, new_status, reason, previous_data, new_data)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (sbom_id)
DO UPDATE SET
    previous_status = EXCLUDED.previous_status,
    new_status      = EXCLUDED.new_status,
    reason          = EXCLUDED.reason,
    previous_data   = EXCLUDED.previous_data,
    new_data        = EXCLUDED.new_data,
    first_seen_at   = now();

-- name: GetProvenanceDriftPending :one
SELECT sbom_id, previous_status, new_status, reason, previous_data, new_data, first_seen_at
FROM provenance_drift_pending
WHERE sbom_id = $1;

-- name: DeleteProvenanceDriftPending :exec
DELETE FROM provenance_drift_pending WHERE sbom_id = $1;
