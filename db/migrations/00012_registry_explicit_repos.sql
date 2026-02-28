-- +goose Up
ALTER TABLE registry
    ADD COLUMN repositories TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE registry
    DROP COLUMN IF EXISTS repositories;
