-- +goose Up
CREATE TABLE scan_jobs (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    registry_id  UUID        NULL REFERENCES registry(id) ON DELETE SET NULL,
    repository   TEXT        NOT NULL,
    digest       TEXT        NOT NULL,
    tag          TEXT        NULL,
    state        TEXT        NOT NULL CHECK (state IN ('queued','running','succeeded','failed')) DEFAULT 'queued',
    attempts     INT         NOT NULL DEFAULT 0,
    last_error   TEXT        NULL,
    nats_msg_id  TEXT        NULL UNIQUE,
    sbom_id      UUID        NULL REFERENCES sbom(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ NULL,
    finished_at  TIMESTAMPTZ NULL
);
CREATE INDEX idx_scan_jobs_state_created ON scan_jobs (state, created_at);
CREATE INDEX idx_scan_jobs_registry_id   ON scan_jobs (registry_id);

-- +goose Down
DROP TABLE IF EXISTS scan_jobs;
