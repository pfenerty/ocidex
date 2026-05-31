-- +goose Up
-- Partial indexes for the outbox-pattern poll loop and stuck-running sweep.
-- The poll loop reads the next queued row(s) by created_at; the sweep
-- targets running rows whose last_attempt_at is older than a threshold.
CREATE INDEX IF NOT EXISTS idx_scan_jobs_queued
    ON scan_jobs (created_at)
    WHERE state = 'queued';

CREATE INDEX IF NOT EXISTS idx_scan_jobs_running
    ON scan_jobs (last_attempt_at)
    WHERE state = 'running';

-- +goose Down
DROP INDEX IF EXISTS idx_scan_jobs_queued;
DROP INDEX IF EXISTS idx_scan_jobs_running;
