-- Namespace is the authorization anchor (ADR-039): ownership and visibility live
-- here and nowhere else. Everything about *how* an SBOM arrived belongs on
-- source; everything that needs an OCI manifest belongs on registry.

-- name: CreateNamespace :one
INSERT INTO namespace (name, owner_id, visibility)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetNamespace :one
SELECT * FROM namespace WHERE id = $1;

-- name: GetNamespaceByName :one
SELECT * FROM namespace WHERE name = $1;

-- name: ListNamespaces :many
SELECT * FROM namespace
WHERE (
    sqlc.narg('is_admin')::boolean = true
    OR visibility = 'public'
    OR (sqlc.narg('user_id')::uuid IS NOT NULL AND owner_id = sqlc.narg('user_id')::uuid)
)
ORDER BY created_at ASC;

-- name: UpdateNamespace :one
UPDATE namespace
SET name       = $2,
    owner_id   = $3,
    visibility = $4,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteNamespace :execrows
DELETE FROM namespace WHERE id = $1;

-- name: CountOwnedPrivateNamespaces :one
-- A viewer who owns no private namespace sees exactly the public set, i.e. the
-- same data as an anonymous viewer. The dashboard-stats cache uses this to
-- collapse such viewers onto the shared anonymous scope instead of minting a
-- per-user scope that the background warmer can never enumerate.
SELECT COUNT(*) FROM namespace
WHERE owner_id = @owner_id AND visibility <> 'public';
