-- +goose Up
ALTER TABLE registry ADD COLUMN include_untagged BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE registry DROP COLUMN include_untagged;
