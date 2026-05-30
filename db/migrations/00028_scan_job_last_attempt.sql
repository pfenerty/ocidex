-- +goose Up
ALTER TABLE scan_jobs ADD COLUMN last_attempt_at TIMESTAMPTZ NULL;

-- +goose Down
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS last_attempt_at;
