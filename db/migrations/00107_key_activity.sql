-- +goose Up

-- What agent keys did (ADR-0058 A5). One row per request an agent key made that
-- changed something or was refused: writes, holds (202), and 401/403/429.
-- Reads that succeeded are not recorded; an agent reads constantly and the
-- interesting question is what it did or tried to do.
--
-- The user is the key's holder, on whose behalf the agent acted; the key,
-- label and tool say which agent and how. tool is the MCP tool name the
-- ocidex-mcp server reports, honoured only from agent keys.
CREATE TABLE key_activity (
    id                BIGSERIAL   PRIMARY KEY,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    api_key_id        UUID        NOT NULL REFERENCES api_key (id) ON DELETE CASCADE,
    user_id           UUID        NOT NULL REFERENCES ocidex_user (id) ON DELETE CASCADE,
    agent_label       TEXT,
    tool              TEXT,
    method            TEXT        NOT NULL,
    route             TEXT        NOT NULL,
    path              TEXT        NOT NULL,
    status            INT         NOT NULL,
    pending_action_id UUID        REFERENCES pending_action (id) ON DELETE SET NULL
);

CREATE INDEX idx_key_activity_key ON key_activity (api_key_id, occurred_at DESC);

-- +goose Down
DROP TABLE IF EXISTS key_activity;
