-- The visibility rule stops meaning "you own it" and starts meaning "you are in
-- it" (ocidex-y0hg.3, ADR-046).
--
-- This is the whole of the reader change. The rule lives in three function
-- bodies, not in the 67 query call sites that invoke them, so replacing one
-- disjunct in each is what makes every read path membership-aware; no call site
-- moves. That property is why ADR-039 put the rule in functions in the first
-- place, and this migration is the first time it has been cashed in.
--
-- In each function, `owner_id = viewer_id` becomes an EXISTS over
-- namespace_member. The other disjuncts — admin, public, and the IS NULL arms —
-- are carried through unchanged. Because 00065 backfilled one owner row per
-- namespace with an owner_id, the two predicates return the same answer for
-- every row that exists today: this migration is a no-op on current data and a
-- widening only for namespaces that later gain a second member. namespace.owner_id
-- is still there and still written; ocidex-y0hg.4 retires it.
--
-- viewer_id IS NULL (an anonymous caller) makes the EXISTS false, exactly as
-- `owner_id = NULL` evaluated to NULL and never to true. The anonymous answer is
-- unchanged: public namespaces only.
--
-- PERFORMANCE. 00052 records the shape this must preserve: the components list
-- went from 3,818 ms to 100 ms by letting the planner evaluate the rule once per
-- namespace and semi-join, instead of once per rollup row (121,080 calls to
-- distinguish eight registries). The set-returning functions keep that shape,
-- the EXISTS added inside them is answered by namespace_member's primary key,
-- and namespace_member_user_id_idx keeps the user-keyed lookups cheap. Callers
-- must keep using `namespace_id IS NULL OR namespace_id IN (SELECT ...)`; do not
-- inline the rule at a call site and do not add a per-row form of the two new
-- functions.

-- +goose Up

-- Set-returning form, for the rollup read paths. 00052's shape exactly; only the
-- third disjunct changes.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION visible_namespace_ids(viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT n.id FROM namespace n
  WHERE COALESCE(viewer_is_admin, false)
     OR n.visibility = 'public'
     OR EXISTS (
          SELECT 1 FROM namespace_member m
          WHERE m.namespace_id = n.id AND m.user_id = viewer_id
        )
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sbom_visible(ns_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR ns_id IS NULL
      OR EXISTS (
           SELECT 1 FROM namespace n
           WHERE n.id = ns_id
             AND (n.visibility = 'public'
                  OR EXISTS (
                       SELECT 1 FROM namespace_member m
                       WHERE m.namespace_id = n.id AND m.user_id = viewer_id
                     ))
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION artifact_visible(a_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR NOT EXISTS (SELECT 1 FROM artifact_namespace WHERE artifact_id = a_id)
      OR EXISTS (
           SELECT 1
           FROM artifact_namespace an
           JOIN namespace n ON n.id = an.namespace_id
           WHERE an.artifact_id = a_id
             AND (n.visibility = 'public'
                  OR EXISTS (
                       SELECT 1 FROM namespace_member m
                       WHERE m.namespace_id = n.id AND m.user_id = viewer_id
                     ))
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

-- "Mine", for the /api/v1/users/me/* feeds and the dashboard panels. It replaces
-- the `owner_id = user_id` predicate that sits behind VisibilityFilter.OwnedOnly
-- today, so those feeds keep working once the column goes in ocidex-y0hg.4.
--
-- Mine now means any membership, not the owner role. That is the right meaning
-- for a Workspace panel: a security engineer's workspace should list the
-- namespaces they are in, not the empty set. It is deliberately narrower than
-- visible_namespace_ids in the other direction — it excludes public namespaces
-- belonging to other people, which is the distinction the /users/me/* rules are
-- built on (ocidex-998g.2).
--
-- It takes no viewer_is_admin argument, and that omission is the point: an admin
-- asking for their own namespaces means their own, not the installation's.
-- +goose StatementBegin
CREATE FUNCTION owned_namespace_ids(viewer_id UUID)
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT m.namespace_id FROM namespace_member m WHERE m.user_id = viewer_id
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION owned_namespace_ids(UUID) IS
    'Namespaces the viewer is a member of, in any role. The "mine" set behind VisibilityFilter.OwnedOnly: narrower than visible_namespace_ids because it excludes others'' public namespaces, and admin-blind because "mine" means mine.';

-- Row-level capability filtering: "which namespaces may I ingest into", as
-- opposed to the operation-level question "may I ingest at all".
--
-- The third argument is the set of roles that grant the capability, not the
-- capability name. That is a deliberate departure from the obvious signature.
-- The epic's standing decision is that roles map to capabilities at compile
-- time, with no DB-defined roles; putting a capability -> roles table in SQL
-- would be a second copy of internal/authz's roleCaps, free to drift, and a
-- drift between two authorization tables is a privilege bug that no test on
-- either side can see. Callers pass authz.RolesWith(cap), which is the only
-- thing that resolves a capability to roles anywhere in the system.
--
-- There is no public disjunct. A public namespace is readable by anyone and
-- writable by nobody who is not a member, which is exactly the difference
-- between this function and visible_namespace_ids.
-- +goose StatementBegin
CREATE FUNCTION namespace_ids_with_capability(viewer_id UUID, viewer_is_admin BOOLEAN, capable_roles TEXT[])
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT n.id FROM namespace n
  WHERE COALESCE(viewer_is_admin, false)
     OR EXISTS (
          SELECT 1 FROM namespace_member m
          WHERE m.namespace_id = n.id
            AND m.user_id = viewer_id
            AND m.role = ANY(capable_roles)
        )
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION namespace_ids_with_capability(UUID, BOOLEAN, TEXT[]) IS
    'Namespaces where the viewer holds a capability, given the roles that grant it (authz.RolesWith). Same set-returning shape as visible_namespace_ids, and deliberately without a public disjunct: public means readable, not writable.';

-- +goose Down

DROP FUNCTION IF EXISTS namespace_ids_with_capability(UUID, BOOLEAN, TEXT[]);
DROP FUNCTION IF EXISTS owned_namespace_ids(UUID);

-- The three bodies as 00053 left them, reading namespace.owner_id. Reversing is
-- lossless only while owner_id is still maintained, which is true until
-- ocidex-y0hg.4; after that this down-migration must be run together with
-- that one's.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION visible_namespace_ids(viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT id FROM namespace
  WHERE COALESCE(viewer_is_admin, false)
     OR visibility = 'public'
     OR owner_id = viewer_id
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION sbom_visible(ns_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR ns_id IS NULL
      OR EXISTS (
           SELECT 1 FROM namespace
           WHERE id = ns_id
             AND (visibility = 'public' OR owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION artifact_visible(a_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS BOOLEAN AS $$
  SELECT COALESCE(viewer_is_admin, false)
      OR NOT EXISTS (SELECT 1 FROM artifact_namespace WHERE artifact_id = a_id)
      OR EXISTS (
           SELECT 1
           FROM artifact_namespace an
           JOIN namespace n ON n.id = an.namespace_id
           WHERE an.artifact_id = a_id
             AND (n.visibility = 'public' OR n.owner_id = viewer_id)
         )
$$ LANGUAGE SQL STABLE;
-- +goose StatementEnd
