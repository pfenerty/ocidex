-- namespace.owner_id goes away (ocidex-y0hg.4, ADR-046).
--
-- 00065 added namespace_member and backfilled it; 00066 moved the three
-- visibility functions onto it. Between those two migrations and this one there
-- are two sources of truth for ownership — the column and the owner row — and a
-- namespace whose owner is changed through one of them is silently wrong to
-- every reader of the other. This migration closes that window.
--
-- namespace_owner() is what lets the read paths keep projecting an owner without
-- a hand-rolled join in each of the eleven queries that want one. It is
-- deliberately a scalar accessor and not a visibility rule: nothing in it
-- decides who may see anything, so it does not belong with the three functions
-- 00066 rewrote and no call site should ever filter on it. Filtering is
-- owned_namespace_ids() and namespace_ids_with_capability(); this is for
-- rendering "owned by" in a response body.
--
-- namespace_one_owner makes the subquery return at most one row, so the scalar
-- form is total rather than a LIMIT 1 papering over duplicates.

-- +goose Up

-- +goose StatementBegin
CREATE FUNCTION namespace_owner(ns_id UUID)
RETURNS UUID
LANGUAGE sql
STABLE
AS $$
  SELECT m.user_id FROM namespace_member m
  WHERE m.namespace_id = ns_id AND m.role = 'owner'
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION namespace_owner(UUID) IS
    'The user_id of a namespace''s owner member, or NULL if it has none. For rendering an owner in a response; never for filtering — use owned_namespace_ids or namespace_ids_with_capability.';

ALTER TABLE namespace DROP COLUMN owner_id;

-- +goose Down

-- Restores the column from the owner rows. Lossless for ownership; the other
-- four roles have no representation in the old model and stay in
-- namespace_member, which 00065's own down-migration discards.
ALTER TABLE namespace
    ADD COLUMN owner_id UUID REFERENCES ocidex_user (id) ON DELETE SET NULL;

UPDATE namespace n
SET owner_id = m.user_id
FROM namespace_member m
WHERE m.namespace_id = n.id AND m.role = 'owner';

DROP FUNCTION IF EXISTS namespace_owner(UUID);
