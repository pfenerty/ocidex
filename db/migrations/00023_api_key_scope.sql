-- +goose Up
ALTER TABLE api_key
    ADD COLUMN scope TEXT NOT NULL DEFAULT 'read-write'
        CHECK (scope IN ('read', 'read-write'));

-- +goose Down
ALTER TABLE api_key DROP COLUMN scope;
