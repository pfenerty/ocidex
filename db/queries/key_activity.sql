-- name: RecordKeyActivity :exec
INSERT INTO key_activity (api_key_id, user_id, agent_label, tool, method, route, path, status, pending_action_id)
VALUES (@api_key_id, @user_id, sqlc.narg('agent_label'), sqlc.narg('tool'), @method, @route, @path, @status,
        sqlc.narg('pending_action_id'));

-- name: ListKeyActivity :many
-- One key's activity, newest first. The caller is the key's holder, or an
-- admin; anyone else gets nothing, which the API turns into 404.
SELECT a.* FROM key_activity a
JOIN api_key k ON k.id = a.api_key_id
WHERE a.api_key_id = @api_key_id
  AND (k.user_id = @viewer_id OR @is_admin::boolean)
  AND (NOT @has_cursor::boolean OR a.id < @cursor_id::bigint)
ORDER BY a.id DESC
LIMIT @row_limit;
