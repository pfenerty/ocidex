-- name: GetUserByIdentity :one
SELECT u.*
FROM ocidex_user u
JOIN user_identity i ON i.user_id = u.id
WHERE i.provider = $1
  AND i.subject  = $2;

-- name: CreateUserWithIdentity :one
-- The account and its first identity are written by one statement so a failure
-- between them cannot leave an account nobody can sign in to.
--
-- github_id/github_username are still populated for the GitHub provider (NULL
-- for every other) because the columns survive one release: a rollback to a
-- binary that still reads them must find an account created in the meantime.
-- Both go away with the columns in ocidex-iqkt.5.
WITH new_user AS (
    INSERT INTO ocidex_user (display_name, email, github_id, github_username)
    VALUES (sqlc.arg(display_name), sqlc.narg(email), sqlc.narg(github_id), sqlc.narg(github_username))
    RETURNING *
), new_identity AS (
    INSERT INTO user_identity (user_id, provider, subject, email)
    SELECT id, sqlc.arg(provider), sqlc.arg(subject), sqlc.narg(email) FROM new_user
)
SELECT * FROM new_user;

-- name: TouchUserProfile :one
-- Refresh the cosmetic fields from whatever the issuer released this sign-in.
-- An issuer that released nothing must not blank what another one set, hence
-- COALESCE over NULLIF rather than a plain assignment.
UPDATE ocidex_user
SET display_name = COALESCE(NULLIF(sqlc.arg(display_name)::text, ''), display_name),
    email        = COALESCE(NULLIF(sqlc.arg(email)::text, ''), email),
    updated_at   = now()
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: UpsertIdentityEmail :exec
-- Keep the identity row's own email in step with the issuer. It is separate
-- from ocidex_user.email because an account may hold several identities and
-- each carries the address its issuer knows.
UPDATE user_identity
SET email      = COALESCE(NULLIF(sqlc.arg(email)::text, ''), email),
    updated_at = now()
WHERE provider = sqlc.arg(provider)
  AND subject  = sqlc.arg(subject);

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
SELECT s.*, u.display_name, u.role
FROM session s
JOIN ocidex_user u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.expires_at > now();

-- name: DeleteSession :exec
DELETE FROM session WHERE token_hash = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM session WHERE expires_at <= now();

-- name: CreateAPIKey :one
INSERT INTO api_key (user_id, name, key_hash, prefix, capabilities)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetAPIKeyByHash :one
SELECT k.id, k.user_id, k.name, k.key_hash, k.prefix, k.capabilities, k.created_at, k.last_used_at,
       u.display_name, u.role
FROM api_key k
JOIN ocidex_user u ON u.id = k.user_id
WHERE k.key_hash = $1;

-- name: TouchAPIKeyLastUsed :exec
UPDATE api_key SET last_used_at = now() WHERE id = $1;

-- name: ListAPIKeysByUser :many
SELECT id, name, prefix, capabilities, created_at, last_used_at
FROM api_key
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: DeleteAPIKey :execrows
DELETE FROM api_key WHERE id = $1 AND user_id = $2;
