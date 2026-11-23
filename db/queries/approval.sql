-- Pending actions: agent writes held for a person's approval (ADR-0058 A4).

-- name: CreatePendingAction :one
INSERT INTO pending_action (api_key_id, user_id, namespace_id, capability, method, path, body,
                            effect, reason, agent_label, expires_at)
VALUES (@api_key_id, @user_id, @namespace_id, @capability, @method, @path, @body,
        @effect, sqlc.narg('reason'), sqlc.narg('agent_label'), @expires_at)
RETURNING *;

-- name: GetPendingAction :one
SELECT * FROM pending_action WHERE id = $1;

-- name: ListPendingActionsFor :many
-- Actions a person may see: ones their own keys asked for, and ones in
-- namespaces they belong to (or every namespace, for an admin). Whether they may
-- approve a given one is decided per row by the capability check, not here.
SELECT * FROM pending_action pa
WHERE (pa.user_id = @viewer_id
       OR @is_admin::boolean
       OR pa.namespace_id IN (SELECT m.namespace_id FROM namespace_member m WHERE m.user_id = @viewer_id))
  AND (sqlc.narg('status')::text IS NULL OR pa.status = sqlc.narg('status')::text)
ORDER BY pa.created_at DESC
LIMIT 200;

-- name: DecidePendingAction :one
-- Moves a pending, unexpired action to approved or denied. The status and
-- expiry are re-checked under the row lock, so two approvers racing decide it
-- once, and a late approval of an expired action changes nothing.
UPDATE pending_action
SET status = @status, decided_by = @decided_by, decided_at = now()
WHERE id = @id AND status = 'pending' AND expires_at > now()
RETURNING *;

-- name: ExpirePendingAction :exec
UPDATE pending_action SET status = 'expired'
WHERE id = $1 AND status = 'pending' AND expires_at <= now();

-- name: RecordPendingActionResult :one
-- An approved action ran. Only an approved action moves to executed or failed,
-- which is what makes execution happen at most once.
UPDATE pending_action
SET status = @status, executed_at = now(), result_status = @result_status, result_body = @result_body
WHERE id = @id AND status = 'approved'
RETURNING *;

-- name: GetAPIKeyForExecution :one
-- The key an approved action runs as, looked up by id at execution time: an
-- expired or deleted key runs nothing (ADR-0058 A4, re-authorized on execute).
SELECT k.id, k.user_id, k.capabilities, k.cluster_id, k.kind, k.namespace_ids, k.agent_label,
       k.approval_required, u.display_name, u.role
FROM api_key k
JOIN ocidex_user u ON u.id = k.user_id
WHERE k.id = $1
  AND (k.expires_at IS NULL OR k.expires_at > now());
