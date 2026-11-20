-- API keys may expire. NULL means never, which is every existing key and the
-- default for a new one. An expired key is refused exactly like an unknown one.

-- +goose Up
ALTER TABLE api_key ADD COLUMN expires_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE api_key DROP COLUMN expires_at;
