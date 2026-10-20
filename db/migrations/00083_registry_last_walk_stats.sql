-- +goose Up
-- ADR-0053 S7: what the registry's most recent catalog walk selected, so an
-- admin can see the window at work (and a limit that is too low) without
-- reading logs. Written by every walk path; NULL until the first one.
ALTER TABLE registry ADD COLUMN last_walk_stats JSONB;

-- +goose Down
ALTER TABLE registry DROP COLUMN last_walk_stats;
