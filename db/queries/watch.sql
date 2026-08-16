-- Artifact watchlist (ocidex-998g.3). A watch is a private bookmark, not an
-- ownership or visibility relation — see the 00058 migration.
--
-- Nothing here re-checks visibility. Whether the caller may watch an artifact
-- at all is decided once, at creation, via artifact_visible(); a watch row that
-- exists is a watch the user is entitled to. Re-filtering the list would give a
-- watch that silently vanishes when its artifact's namespace flips private,
-- with no way for the user to see or clear it.

-- name: CreateArtifactWatch :exec
-- Idempotent: watching twice is the same as watching once, which is what an
-- optimistic UI toggle needs when a click is replayed.
INSERT INTO artifact_watch (user_id, artifact_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DeleteArtifactWatch :execrows
DELETE FROM artifact_watch WHERE user_id = $1 AND artifact_id = $2;

-- name: IsArtifactWatched :one
SELECT EXISTS (
    SELECT 1 FROM artifact_watch WHERE user_id = $1 AND artifact_id = $2
) AS watched;

-- name: ListArtifactWatches :many
-- Keyset on (created_at DESC, artifact_id DESC) per ADR-043 rule 2: a new watch
-- is appended at the head of an ordering that never changes underneath it.
-- The caller fetches row_limit+1 to detect whether a further page exists.
SELECT w.artifact_id, w.created_at,
       a.type, a.name, a.group_name, a.purl,
       COUNT(s.id) AS sbom_count
FROM artifact_watch w
JOIN artifact a ON a.id = w.artifact_id
LEFT JOIN sbom s ON s.artifact_id = a.id
WHERE w.user_id = sqlc.arg('user_id')::uuid
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (w.created_at, w.artifact_id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
GROUP BY w.artifact_id, w.created_at, a.type, a.name, a.group_name, a.purl
ORDER BY w.created_at DESC, w.artifact_id DESC
LIMIT @row_limit;
