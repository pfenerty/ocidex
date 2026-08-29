-- Per-namespace membership (ocidex-y0hg.1, ADR-046).
--
-- Until now a namespace had exactly one nullable owner_id and access was
-- binary: you own the namespace or you do not. That cannot express "these five
-- people share this namespace, and the security engineer among them may
-- re-scan but not rotate the registry credential". namespace_member replaces
-- the single owner column with a set of (user, role) pairs.
--
-- Schema only. Nothing reads this table yet, the three visibility functions
-- still consult namespace.owner_id (ocidex-y0hg.3 rewrites them), and owner_id
-- itself stays in place until ocidex-y0hg.4. One risky change at a time —
-- the same discipline 00053's header states for the registry split.
--
-- The role set is closed and mirrors the compile-time capability sets in
-- internal/auth (ocidex-y0hg.2). It lives in a CHECK rather than its own table
-- because roles are not data: adding one is a code change that must ship a
-- capability set with it, and a DB-defined role would have no capabilities.
--
-- namespace_one_owner is load-bearing. It makes "exactly one owner" a database
-- invariant rather than a service-layer convention, which is what lets
-- ocidex-y0hg.7 reject a demote of the last owner by catching a unique
-- violation instead of racing a SELECT against a concurrent UPDATE.
--
-- The backfill is exact: every namespace with an owner_id yields one owner row,
-- and namespaces with a NULL owner_id (created before ownership was recorded,
-- or orphaned by ON DELETE SET NULL) yield none. Those stay ownerless here
-- exactly as they are ownerless today.

-- +goose Up

-- +goose StatementBegin
CREATE TABLE namespace_member (
    namespace_id UUID        NOT NULL REFERENCES namespace (id) ON DELETE CASCADE,
    user_id      UUID        NOT NULL REFERENCES ocidex_user (id) ON DELETE CASCADE,
    role         TEXT        NOT NULL CHECK (role IN
                                 ('owner', 'maintainer', 'security', 'developer', 'viewer')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace_id, user_id)
);
-- +goose StatementEnd

COMMENT ON TABLE namespace_member IS
    'Membership of a namespace, with a per-namespace role. The namespace is the team (ADR-046); this table is what makes it one.';
COMMENT ON COLUMN namespace_member.role IS
    'Closed set, mapped to compile-time capability sets in internal/auth. Not a DB-defined role: a new role is a code change.';

CREATE UNIQUE INDEX namespace_one_owner
    ON namespace_member (namespace_id) WHERE role = 'owner';

COMMENT ON INDEX namespace_one_owner IS
    'Exactly one owner per namespace, as a database invariant. Member management relies on this to reject a demote of the last owner.';

CREATE INDEX namespace_member_user_id_idx ON namespace_member (user_id);

INSERT INTO namespace_member (namespace_id, user_id, role)
SELECT id, owner_id, 'owner' FROM namespace WHERE owner_id IS NOT NULL;

-- +goose Down

-- Restores owner_id from the owner rows before dropping the table, so a
-- down-then-up round trip is lossless for ownership. Roles other than 'owner'
-- have nowhere to go in the old model and are discarded — that is the shape of
-- the data loss, and it is why this is a down-migration and not a rollback
-- plan for a namespace that has grown a real team.
UPDATE namespace n
SET owner_id = m.user_id
FROM namespace_member m
WHERE m.namespace_id = n.id AND m.role = 'owner';

DROP TABLE namespace_member;
