-- API keys gain an 'installation_admin' capability (ADR-046 M5 amendment). An admin's key
-- now passes the admin-only routes only when it carries it, so a key minted for
-- one narrow job no longer acts with the whole admin role.
--
-- No backfill: existing keys hold no 'installation_admin' and lose admin-route access. That
-- is the safe direction; an admin who needs a key for those routes mints one.

-- +goose Up
ALTER TABLE api_key DROP CONSTRAINT api_key_capabilities_known;
ALTER TABLE api_key ADD CONSTRAINT api_key_capabilities_known
    CHECK (capabilities <@ ARRAY[
        'read_private', 'ingest', 'trigger_scan', 'push_inventory', 'delete_artifact',
        'manage_source', 'manage_cluster', 'read_secret', 'manage_member', 'delete_namespace',
        'installation_admin'
    ]::TEXT[]);

-- +goose Down
UPDATE api_key SET capabilities = array_remove(capabilities, 'installation_admin');
ALTER TABLE api_key DROP CONSTRAINT api_key_capabilities_known;
ALTER TABLE api_key ADD CONSTRAINT api_key_capabilities_known
    CHECK (capabilities <@ ARRAY[
        'read_private', 'ingest', 'trigger_scan', 'push_inventory', 'delete_artifact',
        'manage_source', 'manage_cluster', 'read_secret', 'manage_member', 'delete_namespace'
    ]::TEXT[]);
