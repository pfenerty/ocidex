-- +goose Up
CREATE TABLE ocidex_user (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id       BIGINT NOT NULL UNIQUE,
    github_username TEXT   NOT NULL,
    role            TEXT   NOT NULL DEFAULT 'viewer'
                        CHECK (role IN ('admin','member','viewer')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE session (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES ocidex_user(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,  -- hex(SHA-256(raw_token))
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON session (token_hash);
CREATE INDEX ON session (user_id);

CREATE TABLE api_key (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES ocidex_user(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,  -- hex(SHA-256(raw_key))
    prefix       TEXT NOT NULL,         -- first 8 chars of raw key for display
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX ON api_key (key_hash);
CREATE INDEX ON api_key (user_id);

-- +goose Down
DROP TABLE IF EXISTS api_key;
DROP TABLE IF EXISTS session;
DROP TABLE IF EXISTS ocidex_user;
