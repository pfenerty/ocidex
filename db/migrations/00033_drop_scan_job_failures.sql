-- +goose Up
-- scan_job_failures was the audit table for the DLQ-via-NATS subject. Under
-- the outbox pattern (ADR-0024), 'failed' is the only DLQ — scan_jobs.state +
-- last_error carry everything operators need. The table has not been written
-- to since the atomic-switch commit; legacy rows have been aged out by the
-- retention purge.
DROP TABLE IF EXISTS scan_job_failures;

-- +goose Down
CREATE TABLE scan_job_failures (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    nats_msg_id    TEXT,
    payload        JSONB       NOT NULL,
    failure_reason TEXT        NOT NULL,
    delivery_count INT         NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scan_job_failures_created_at_idx ON scan_job_failures (created_at DESC);
