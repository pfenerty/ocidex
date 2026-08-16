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
-- Two selection paths, one query (ocidex-998g.2).
--
-- The default is the *visibility* path: admin, or public, or mine. The
-- owned_only path backs /api/v1/users/me/* and is strictly narrower — it drops
-- the public-but-not-mine rows that the visibility path is obliged to include,
-- and it ignores is_admin, because "my namespaces" means mine even for an
-- admin. Keeping both in one query is what stops the me-scoped feeds from
-- drifting away from the ones they mirror.
--
-- `owner_id = NULL` evaluates to NULL rather than true, so an unauthenticated
-- caller on the ownership path matches nothing.
SELECT * FROM namespace
WHERE (
    CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
         THEN owner_id = sqlc.narg('user_id')::uuid
         ELSE sqlc.narg('is_admin')::boolean = true
              OR visibility = 'public'
              OR (sqlc.narg('user_id')::uuid IS NOT NULL AND owner_id = sqlc.narg('user_id')::uuid)
    END
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
