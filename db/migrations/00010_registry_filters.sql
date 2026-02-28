-- +goose Up
ALTER TABLE registry
    ADD COLUMN repository_patterns TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN tag_patterns         TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE registry
    DROP COLUMN IF EXISTS repository_patterns,
    DROP COLUMN IF EXISTS tag_patterns;
