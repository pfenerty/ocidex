-- +goose Up
-- ocidex-70eo.5 (ADR-0044 K8 amendment): an API key bound to one cluster. A
-- bound key can do nothing but push that cluster's inventory: its ceiling is
-- push_inventory alone (the CHECK below), and the API rejects it on every
-- other route. The key still belongs to the user who minted it, so it also
-- narrows with that user's live namespace roles (ADR-046).
--
-- ON DELETE CASCADE: deleting the cluster revokes its agent credentials. A
-- credential for a cluster that no longer exists has nothing it may do.
ALTER TABLE api_key ADD COLUMN cluster_id UUID REFERENCES cluster(id) ON DELETE CASCADE;
ALTER TABLE api_key ADD CONSTRAINT api_key_cluster_push_only
    CHECK (cluster_id IS NULL OR capabilities = ARRAY['push_inventory']::text[]);
CREATE INDEX api_key_cluster_id_idx ON api_key (cluster_id) WHERE cluster_id IS NOT NULL;

COMMENT ON COLUMN api_key.cluster_id IS
    'Set for a cluster agent credential: the key may only push this cluster''s inventory. NULL for an ordinary key.';

-- +goose Down
DELETE FROM api_key WHERE cluster_id IS NOT NULL;
DROP INDEX api_key_cluster_id_idx;
ALTER TABLE api_key DROP CONSTRAINT api_key_cluster_push_only;
ALTER TABLE api_key DROP COLUMN cluster_id;
