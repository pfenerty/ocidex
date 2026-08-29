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

-- Membership (ocidex-y0hg.1). Nothing reads these yet: the visibility functions
-- still consult namespace.owner_id until ocidex-y0hg.3, and member management
-- lands in ocidex-y0hg.7. They are generated now so the schema change and the
-- repository surface it implies land in one migration-shaped commit.

-- name: AddNamespaceMember :one
-- Idempotent on (namespace_id, user_id): re-adding an existing member changes
-- their role rather than failing, which is what the member-management PUT wants.
-- Promoting someone to 'owner' while another owner exists violates
-- namespace_one_owner and surfaces as a unique violation, by design.
INSERT INTO namespace_member (namespace_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (namespace_id, user_id) DO UPDATE
SET role = EXCLUDED.role
RETURNING *;

-- name: GetNamespaceMember :one
SELECT * FROM namespace_member
WHERE namespace_id = $1 AND user_id = $2;

-- name: ListNamespaceMembers :many
-- Owner first, then by join order, so the caller never has to sort a role
-- string to find who is answerable for the namespace.
SELECT * FROM namespace_member
WHERE namespace_id = $1
ORDER BY (role = 'owner') DESC, created_at ASC;

-- name: ListNamespaceMembershipsForUser :many
-- One user's memberships across every namespace. Backs the me-scoped feeds that
-- ListNamespaces currently answers from owner_id.
SELECT * FROM namespace_member
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: RemoveNamespaceMember :execrows
DELETE FROM namespace_member
WHERE namespace_id = $1 AND user_id = $2;
