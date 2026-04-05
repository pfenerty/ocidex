-- name: CreateRegistry :one
INSERT INTO registry (name, type, url, insecure, webhook_secret, repository_patterns, tag_patterns, scan_mode, poll_interval_minutes, repositories, auth_username, auth_token)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetRegistry :one
SELECT * FROM registry WHERE id = $1;

-- name: ListRegistries :many
SELECT * FROM registry ORDER BY created_at ASC;

-- name: UpdateRegistry :one
UPDATE registry
SET name                 = $2,
    type                 = $3,
    url                  = $4,
    insecure             = $5,
    webhook_secret       = $6,
    enabled              = $7,
    repository_patterns  = $8,
    tag_patterns         = $9,
    scan_mode            = $10,
    poll_interval_minutes = $11,
    repositories         = $12,
    auth_username        = $13,
    auth_token           = $14,
    updated_at           = now()
WHERE id = $1
RETURNING *;

-- name: SetRegistryEnabled :one
UPDATE registry
SET enabled    = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateRegistryLastPolled :one
UPDATE registry
SET last_polled_at = now(), updated_at = now()
WHERE id = $1
RETURNING *;

-- name: ListPollableRegistries :many
SELECT * FROM registry
WHERE enabled = true AND scan_mode IN ('poll', 'both')
ORDER BY created_at ASC;

-- name: DeleteRegistry :execrows
DELETE FROM registry WHERE id = $1;
