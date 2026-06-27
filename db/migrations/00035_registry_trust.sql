-- +goose Up
ALTER TABLE registry ADD COLUMN verification_mode TEXT NOT NULL DEFAULT 'none'
    CHECK (verification_mode IN ('none', 'public_key', 'keyless'));
ALTER TABLE registry ADD COLUMN trust_public_key TEXT;
ALTER TABLE registry ADD COLUMN trust_identity TEXT;
ALTER TABLE registry ADD COLUMN trust_issuer TEXT;

-- +goose Down
ALTER TABLE registry DROP COLUMN trust_issuer;
ALTER TABLE registry DROP COLUMN trust_identity;
ALTER TABLE registry DROP COLUMN trust_public_key;
ALTER TABLE registry DROP COLUMN verification_mode;
