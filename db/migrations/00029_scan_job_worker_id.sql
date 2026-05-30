-- +goose Up
ALTER TABLE scan_jobs ADD COLUMN worker_id TEXT NULL;

-- +goose Down
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS worker_id;
