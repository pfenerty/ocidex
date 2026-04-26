-- name: UpsertUser :one
INSERT INTO ocidex_user (github_id, github_username)
VALUES ($1, $2)
ON CONFLICT (github_id) DO UPDATE
    SET github_username = EXCLUDED.github_username,
        updated_at      = now()
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM ocidex_user WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM ocidex_user ORDER BY created_at ASC;

-- name: UpdateUserRole :one
UPDATE ocidex_user
SET role       = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: CreateSession :one
INSERT INTO session (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSessionByTokenHash :one
SELECT s.*, u.github_id, u.github_username, u.role
FROM session s
JOIN ocidex_user u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.expires_at > now();

-- name: DeleteSession :exec
DELETE FROM session WHERE token_hash = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM session WHERE expires_at <= now();

-- name: CreateAPIKey :one
INSERT INTO api_key (user_id, name, key_hash, prefix, scope)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAPIKeyByHash :one
SELECT k.id, k.user_id, k.name, k.key_hash, k.prefix, k.scope, k.created_at, k.last_used_at,
       u.github_id, u.github_username, u.role
FROM api_key k
JOIN ocidex_user u ON u.id = k.user_id
WHERE k.key_hash = $1;

-- name: TouchAPIKeyLastUsed :exec
UPDATE api_key SET last_used_at = now() WHERE id = $1;

-- name: ListAPIKeysByUser :many
SELECT id, name, prefix, scope, created_at, last_used_at
FROM api_key
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: DeleteAPIKey :execrows
DELETE FROM api_key WHERE id = $1 AND user_id = $2;
