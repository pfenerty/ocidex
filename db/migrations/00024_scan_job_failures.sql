-- +goose Up
CREATE TABLE scan_job_failures (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    nats_msg_id    TEXT,
    payload        JSONB       NOT NULL,
    failure_reason TEXT        NOT NULL,
    delivery_count INT         NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX scan_job_failures_created_at_idx ON scan_job_failures (created_at DESC);

-- +goose Down
DROP TABLE scan_job_failures;
