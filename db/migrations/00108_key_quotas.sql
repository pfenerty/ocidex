-- +goose Up

-- Write budgets for agent keys (ADR-0058 A6). A runaway or prompt-injected
-- agent is bounded by how much it can do per hour, independently of approvals:
-- a held request counts when it is asked for, so asking repeatedly for
-- approval is bounded too.
--
-- NULL is the default for the key's kind; a value overrides it within the
-- installation maximum the API enforces.
ALTER TABLE api_key
    ADD COLUMN scans_per_hour  INT CHECK (scans_per_hour  IS NULL OR scans_per_hour  >= 0),
    ADD COLUMN writes_per_hour INT CHECK (writes_per_hour IS NULL OR writes_per_hour >= 0);

-- One counter per key, action class and hour. Rows for past hours are dead
-- weight; the consume query deletes the key's stale rows as it goes.
CREATE TABLE key_quota_window (
    api_key_id   UUID        NOT NULL REFERENCES api_key (id) ON DELETE CASCADE,
    class        TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    used         INT         NOT NULL,
    PRIMARY KEY (api_key_id, class, window_start)
);

-- +goose Down
DROP TABLE IF EXISTS key_quota_window;
ALTER TABLE api_key DROP COLUMN IF EXISTS writes_per_hour, DROP COLUMN IF EXISTS scans_per_hour;
