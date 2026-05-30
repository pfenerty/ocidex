-- +goose Up
ALTER TABLE scan_jobs
    ADD COLUMN reconcile_attempts INT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE scan_jobs
    DROP COLUMN reconcile_attempts;
