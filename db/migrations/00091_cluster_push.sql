-- +goose Up
-- ocidex-70eo.4: recent push attempts per cluster, rejected ones included, so a
-- broken agent says why instead of only going stale. Bounded per cluster by
-- the recording query (PruneClusterPushes); this is a diagnostic tail, not an
-- audit log.
CREATE TABLE cluster_push (
    id            BIGSERIAL PRIMARY KEY,
    cluster_id    UUID NOT NULL REFERENCES cluster(id) ON DELETE CASCADE,
    at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted      BOOLEAN NOT NULL,
    status        INTEGER NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    workloads     INTEGER,
    agent_version TEXT
);
CREATE INDEX cluster_push_cluster_id_idx ON cluster_push (cluster_id, id DESC);

COMMENT ON TABLE cluster_push IS
    'Recent inventory push attempts per cluster, accepted and rejected. Capped per cluster on insert.';

-- The last rejection, denormalized so a cluster list derives health without a
-- join. Erroring means this is newer than last_seen_at.
ALTER TABLE cluster
    ADD COLUMN last_push_error_at TIMESTAMPTZ,
    ADD COLUMN last_push_error    TEXT;

-- +goose Down
ALTER TABLE cluster DROP COLUMN last_push_error_at, DROP COLUMN last_push_error;
DROP TABLE cluster_push;
