-- +goose Up
ALTER TABLE registry ADD COLUMN auth_username TEXT;
ALTER TABLE registry ADD COLUMN auth_token TEXT;
ALTER TABLE registry DROP CONSTRAINT registry_type_check;
ALTER TABLE registry ADD CONSTRAINT registry_type_check CHECK (type IN ('zot', 'harbor', 'docker', 'generic', 'ghcr'));

-- +goose Down
ALTER TABLE registry DROP COLUMN auth_token;
ALTER TABLE registry DROP COLUMN auth_username;
ALTER TABLE registry DROP CONSTRAINT registry_type_check;
ALTER TABLE registry ADD CONSTRAINT registry_type_check CHECK (type IN ('zot', 'harbor', 'docker', 'generic'));
