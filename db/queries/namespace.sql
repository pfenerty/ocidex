-- Namespace is the authorization anchor (ADR-039): ownership and visibility live
-- here and nowhere else. Everything about *how* an SBOM arrived belongs on
-- source; everything that needs an OCI manifest belongs on registry.

-- name: CreateNamespace :one
-- Creating a namespace creates its owner member in the same statement
-- (ocidex-y0hg.4). Two statements would leave a window in which a namespace
-- exists with nobody in it, and a caller that crashed inside that window would
-- leave an orphan nobody can administer.
--
-- A NULL owner_user_id creates an ownerless namespace, which is what the
-- registry-import path does when it has no user to attribute. The member INSERT
-- then selects no rows rather than failing, and the projected owner is NULL.
WITH ns AS (
    INSERT INTO namespace (name, visibility)
    VALUES (@name, @visibility)
    RETURNING *
), owner_row AS (
    INSERT INTO namespace_member (namespace_id, user_id, role)
    SELECT ns.id, sqlc.narg('owner_user_id')::uuid, 'owner'
    FROM ns
    WHERE sqlc.narg('owner_user_id')::uuid IS NOT NULL
    RETURNING user_id
)
SELECT ns.*, (SELECT user_id FROM owner_row) AS owner_id FROM ns;

-- name: GetNamespace :one
SELECT sqlc.embed(n), namespace_owner(n.id) AS owner_id FROM namespace n WHERE n.id = $1;

-- name: GetNamespaceByName :one
SELECT sqlc.embed(n), namespace_owner(n.id) AS owner_id FROM namespace n WHERE n.name = $1;

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
-- Both paths are function calls now rather than inline predicates
-- (ocidex-y0hg.4). "Mine" means any membership, not the owner role: a security
-- engineer's workspace should list the namespaces they are in.
--
-- An unauthenticated caller on the ownership path still matches nothing, but for
-- a different reason than before, and it is worth saying rather than leaving to
-- be re-derived. It used to be that `owner = NULL` evaluates to NULL and never
-- to true; now owned_namespace_ids(NULL) returns the empty set and `id IN
-- (empty set)` is false. Same answer, different mechanism.
SELECT sqlc.embed(n), namespace_owner(n.id) AS owner_id FROM namespace n
WHERE (
    CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
         THEN n.id IN (SELECT owned_namespace_ids(sqlc.narg('user_id')::uuid))
         ELSE n.id IN (SELECT visible_namespace_ids(
                       sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    END
)
ORDER BY n.created_at ASC;

-- name: UpdateNamespace :one
-- Ownership is not transferable here and never was: the handler says so and only
-- ever carried the existing owner forward. With ownership in namespace_member
-- there is nothing to carry, so the parameter is gone rather than reinstated as
-- a no-op. Transferring ownership is member management (ocidex-y0hg.7).
UPDATE namespace
SET name       = $2,
    visibility = $3,
    updated_at = now()
WHERE id = $1
RETURNING *, namespace_owner(id) AS owner_id;

-- name: DeleteNamespace :execrows
DELETE FROM namespace WHERE id = $1;

-- name: CountOwnedPrivateNamespaces :one
-- A viewer who owns no private namespace sees exactly the public set, i.e. the
-- same data as an anonymous viewer. The dashboard-stats cache uses this to
-- collapse such viewers onto the shared anonymous scope instead of minting a
-- per-user scope that the background warmer can never enumerate.
SELECT COUNT(*) FROM namespace
WHERE id IN (SELECT owned_namespace_ids(@viewer_id)) AND visibility <> 'public';

-- Membership (ocidex-y0hg.1). Direct reads and writes of the membership table.
-- The read *paths* deliberately do not use these: visibility goes through the
-- functions 00066 rewrote, which is what keeps one rule in one place. Member
-- management (ocidex-y0hg.7) is what consumes them.

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
-- ListNamespaces answers through owned_namespace_ids.
SELECT * FROM namespace_member
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: RemoveNamespaceMember :execrows
DELETE FROM namespace_member
WHERE namespace_id = $1 AND user_id = $2;
