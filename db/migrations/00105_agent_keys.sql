-- +goose Up

-- Agent keys (ADR-0058 A1, A2).
--
-- kind: a personal key is its holder at the keyboard; an agent key is a
-- program acting for its holder; a cluster key is a cluster agent's push-only
-- credential (cluster_id set). The kind decides which rules apply, so it is a
-- column rather than inferred from the other columns at every check.
--
-- namespace_ids: the namespaces the key may act in and read privately. NULL
-- means every namespace the holder belongs to, which is how every key behaved
-- before this column and is allowed only on personal keys. An agent key must
-- name at least one.
--
-- agent_label: what the holder calls the client ("Claude Code on laptop"), for
-- the key list and the audit log. Free text, never an identifier.
ALTER TABLE api_key
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'personal',
    ADD COLUMN namespace_ids UUID[],
    ADD COLUMN agent_label TEXT;

UPDATE api_key SET kind = 'cluster' WHERE cluster_id IS NOT NULL;

ALTER TABLE api_key
    ADD CONSTRAINT api_key_kind_known CHECK (kind IN ('personal', 'agent', 'cluster')),
    ADD CONSTRAINT api_key_cluster_kind CHECK ((kind = 'cluster') = (cluster_id IS NOT NULL)),
    ADD CONSTRAINT api_key_agent_scoped CHECK (kind <> 'agent' OR cardinality(namespace_ids) >= 1),
    ADD CONSTRAINT api_key_namespaces_nonempty CHECK (namespace_ids IS NULL OR cardinality(namespace_ids) >= 1);

-- Visibility narrowed to a key's namespace set (ADR-0058 A2). Each function is
-- the existing rule with one more condition: a namespace outside the key's set
-- is visible only if it is public. A NULL set is no narrowing, so passing NULL
-- reproduces the two-argument function exactly; that is what a session and an
-- unscoped personal key pass.
--
-- The set applies to admins too. An admin's scoped key is refused outside its
-- namespaces exactly as ADR-046 M5 refuses an admin's narrow key a capability
-- it does not carry.

-- +goose StatementBegin
CREATE FUNCTION visible_namespace_ids(viewer_id UUID, viewer_is_admin BOOLEAN, key_namespaces UUID[])
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT n.id FROM namespace n
  WHERE (n.visibility = 'public'
         OR key_namespaces IS NULL
         OR n.id = ANY (key_namespaces))
    AND (COALESCE(viewer_is_admin, false)
         OR n.visibility = 'public'
         OR EXISTS (
              SELECT 1 FROM namespace_member m
              WHERE m.namespace_id = n.id AND m.user_id = viewer_id
            ))
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION sbom_visible(ns_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN, key_namespaces UUID[])
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
  SELECT sbom_visible(ns_id, viewer_id, viewer_is_admin)
     AND (key_namespaces IS NULL
          OR ns_id IS NULL
          OR ns_id = ANY (key_namespaces)
          OR EXISTS (SELECT 1 FROM namespace n WHERE n.id = ns_id AND n.visibility = 'public'))
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION artifact_visible(a_id UUID, viewer_id UUID, viewer_is_admin BOOLEAN, key_namespaces UUID[])
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
  SELECT CASE
    WHEN key_namespaces IS NULL THEN artifact_visible(a_id, viewer_id, viewer_is_admin)
    ELSE NOT EXISTS (SELECT 1 FROM artifact_namespace WHERE artifact_id = a_id)
      OR EXISTS (
           SELECT 1 FROM artifact_namespace an
           WHERE an.artifact_id = a_id
             AND an.namespace_id IN (SELECT visible_namespace_ids(viewer_id, viewer_is_admin, key_namespaces))
         )
  END
$$;
-- +goose StatementEnd

-- "Mine", narrowed to the key's namespaces.
-- +goose StatementBegin
CREATE FUNCTION owned_namespace_ids(viewer_id UUID, key_namespaces UUID[])
RETURNS SETOF UUID
LANGUAGE sql
STABLE
AS $$
  SELECT m.namespace_id FROM namespace_member m
  WHERE m.user_id = viewer_id
    AND (key_namespaces IS NULL OR m.namespace_id = ANY (key_namespaces))
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS owned_namespace_ids(UUID, UUID[]);
DROP FUNCTION IF EXISTS artifact_visible(UUID, UUID, BOOLEAN, UUID[]);
DROP FUNCTION IF EXISTS sbom_visible(UUID, UUID, BOOLEAN, UUID[]);
DROP FUNCTION IF EXISTS visible_namespace_ids(UUID, BOOLEAN, UUID[]);

ALTER TABLE api_key
    DROP CONSTRAINT IF EXISTS api_key_namespaces_nonempty,
    DROP CONSTRAINT IF EXISTS api_key_agent_scoped,
    DROP CONSTRAINT IF EXISTS api_key_cluster_kind,
    DROP CONSTRAINT IF EXISTS api_key_kind_known,
    DROP COLUMN IF EXISTS agent_label,
    DROP COLUMN IF EXISTS namespace_ids,
    DROP COLUMN IF EXISTS kind;
