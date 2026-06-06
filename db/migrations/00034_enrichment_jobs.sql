-- +goose Up
CREATE TABLE enrichment_jobs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id         UUID        NOT NULL REFERENCES sbom(id) ON DELETE CASCADE,
    state           TEXT        NOT NULL CHECK (state IN ('queued','running','succeeded','failed')) DEFAULT 'queued',
    attempts        INT         NOT NULL DEFAULT 0,
    last_error      TEXT        NULL,
    idempotency_key TEXT        NULL UNIQUE,
    worker_id       TEXT        NULL,
    architecture    TEXT        NULL,
    build_date      TEXT        NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ NULL,
    last_attempt_at TIMESTAMPTZ NULL,
    finished_at     TIMESTAMPTZ NULL
);

CREATE INDEX idx_enrichment_jobs_queued  ON enrichment_jobs (created_at)      WHERE state = 'queued';
CREATE INDEX idx_enrichment_jobs_running ON enrichment_jobs (last_attempt_at) WHERE state = 'running';
CREATE INDEX idx_enrichment_jobs_sbom_id ON enrichment_jobs (sbom_id);

-- +goose Down
DROP TABLE IF EXISTS enrichment_jobs;
