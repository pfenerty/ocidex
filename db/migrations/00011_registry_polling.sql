-- +goose Up
ALTER TABLE registry
    ADD COLUMN scan_mode             TEXT        NOT NULL DEFAULT 'webhook'
                                                 CHECK (scan_mode IN ('webhook', 'poll', 'both')),
    ADD COLUMN poll_interval_minutes INTEGER     NOT NULL DEFAULT 60,
    ADD COLUMN last_polled_at        TIMESTAMPTZ;

-- +goose Down
ALTER TABLE registry
    DROP COLUMN IF EXISTS scan_mode,
    DROP COLUMN IF EXISTS poll_interval_minutes,
    DROP COLUMN IF EXISTS last_polled_at;
