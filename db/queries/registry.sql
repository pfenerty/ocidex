-- name: CreateRegistry :one
INSERT INTO registry (name, type, url, insecure, webhook_secret, repository_patterns, tag_patterns)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetRegistry :one
SELECT * FROM registry WHERE id = $1;

-- name: ListRegistries :many
SELECT * FROM registry ORDER BY created_at ASC;

-- name: UpdateRegistry :one
UPDATE registry
SET name                = $2,
    type                = $3,
    url                 = $4,
    insecure            = $5,
    webhook_secret      = $6,
    enabled             = $7,
    repository_patterns = $8,
    tag_patterns        = $9,
    updated_at          = now()
WHERE id = $1
RETURNING *;

-- name: SetRegistryEnabled :one
UPDATE registry
SET enabled    = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteRegistry :execrows
DELETE FROM registry WHERE id = $1;
