-- API keys carry capabilities, not read/read-write (ocidex-y0hg.8, ADR-046).
--
-- api_key.scope was two values with a hard-coded meaning, and ADR-044's
-- inventory push had to reuse 'read-write' because there was nothing narrower
-- to ask for. A key issued to upload SBOMs could therefore also push workloads
-- into any cluster its owner had. The scope column becomes the capability set
-- the key is allowed to exercise.
--
-- The set is a ceiling, not a grant. At validation time the service INTERSECTS
-- these capabilities with the owner's live namespace_member roles, so a key can
-- never do more than its owner can do *now* — which is what makes "demote a
-- member and their keys narrow immediately, with no rotation" true.
--
-- Backfill:
--
--   'read'       -> {read_private}. A read key reads private content and
--                   nothing else, which is exactly what it did before.
--   'read-write' -> every capability. That is not a widening: the live
--                   intersection means "all capabilities" evaluates to "whatever
--                   my owner may do", which is precisely what a read-write key
--                   already resolved to. Naming the owner's grant set as it
--                   stood at migration time would instead freeze it, and a key
--                   would stop tracking a later promotion.
--
-- The CHECK mirrors the Capability constants in internal/authz for the same
-- reason namespace_member.role does: an unknown capability string is a typo,
-- not a feature, and it should fail at the write rather than deny quietly at
-- every check.

-- +goose Up

ALTER TABLE api_key ADD COLUMN capabilities TEXT[] NOT NULL DEFAULT '{}';

UPDATE api_key SET capabilities = ARRAY['read_private']
WHERE scope = 'read';

UPDATE api_key SET capabilities = ARRAY[
    'read_private', 'ingest', 'trigger_scan', 'push_inventory', 'delete_artifact',
    'manage_source', 'manage_cluster', 'read_secret', 'manage_member', 'delete_namespace'
]
WHERE scope <> 'read';

ALTER TABLE api_key ADD CONSTRAINT api_key_capabilities_known
    CHECK (capabilities <@ ARRAY[
        'read_private', 'ingest', 'trigger_scan', 'push_inventory', 'delete_artifact',
        'manage_source', 'manage_cluster', 'read_secret', 'manage_member', 'delete_namespace'
    ]::TEXT[]);

ALTER TABLE api_key DROP COLUMN scope;

COMMENT ON COLUMN api_key.capabilities IS
    'Ceiling on what this key may do, intersected at validation time with the owner''s live namespace roles. Mirrors the Capability constants in internal/authz.';

-- +goose Down

-- A key is 'read' if it carries nothing beyond read_private; anything wider
-- collapses back to 'read-write'. That is lossy in the same way the old model
-- was: two values cannot hold ten, and a key issued for {ingest} alone comes
-- back as a full read-write key. It is a down-migration, not a rollback plan.
ALTER TABLE api_key ADD COLUMN scope TEXT NOT NULL DEFAULT 'read-write'
    CHECK (scope IN ('read', 'read-write'));

UPDATE api_key SET scope = 'read'
WHERE capabilities <@ ARRAY['read_private']::TEXT[];

ALTER TABLE api_key DROP CONSTRAINT api_key_capabilities_known;
ALTER TABLE api_key DROP COLUMN capabilities;
