-- +goose Up
-- ocidex-70eo.9: retire a cluster without deleting it. A paused cluster
-- refuses snapshots and keeps its last inventory, so images running there stay
-- protected from retention (00086 P2) and nothing it reported is lost.
ALTER TABLE cluster ADD COLUMN paused_at TIMESTAMPTZ;

COMMENT ON COLUMN cluster.paused_at IS
    'Set while the cluster is paused: snapshots are refused and the last inventory is kept. NULL when active.';

-- +goose Down
ALTER TABLE cluster DROP COLUMN paused_at;
