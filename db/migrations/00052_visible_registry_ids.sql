-- Set-returning companion to sbom_visible() for the rollup read paths
-- (ocidex-ckv.2).
--
-- sbom_visible(reg_id, ...) answers the question one registry at a time, with an
-- EXISTS over registry inside. That is the right shape when the caller is
-- filtering the sbom table, which has thousands of rows. It is the wrong shape
-- when the caller is filtering a rollup: EXPLAIN ANALYZE on the components list
-- showed 121,080 calls costing 3,818 ms and 242k buffer hits, to distinguish
-- eight registries.
--
-- This returns the visible set instead, so the planner evaluates the rule once
-- per registry and semi-joins. Same 3,818 ms scan node drops to 100 ms. The
-- three disjuncts are identical to sbom_visible's, so the two agree by
-- construction and the rule still lives in exactly one place.
--
-- Callers must keep the NULL arm themselves — `registry_id IS NULL OR
-- registry_id IN (SELECT ...)` — because a NULL registry_id is visible to
-- everyone (sbom_visible's `reg_id IS NULL` disjunct) but matches no IN list.

-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION visible_registry_ids(viewer_id UUID, viewer_is_admin BOOLEAN)
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT id FROM registry
  WHERE COALESCE(viewer_is_admin, false)
     OR visibility = 'public'
     OR owner_id = viewer_id
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION visible_registry_ids(UUID, BOOLEAN) IS
    'Registries visible to a viewer. Set-returning form of sbom_visible(), for filtering rollup tables where the per-row form costs one EXISTS lookup per rollup row.';

-- +goose Down
DROP FUNCTION IF EXISTS visible_registry_ids(UUID, BOOLEAN);
