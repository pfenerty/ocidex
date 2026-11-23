-- +goose Up

-- Server-held approvals for agent writes (ADR-0058 A4).
--
-- approval_required lists the capabilities a key may use only with a person's
-- approval. It is a subset of the key's ceiling: approving cannot grant what the
-- key does not carry, so a capability outside the ceiling here would be dead.
ALTER TABLE api_key
    ADD COLUMN approval_required TEXT[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT api_key_approval_within_ceiling CHECK (approval_required <@ capabilities);

-- One held request. The stored method, path and body are what runs on
-- approval, byte for byte: the approver approves the effect OCIDex rendered
-- from this request, and nothing the agent can change afterwards.
--
-- reason is text the agent supplied. It is shown to the approver as an
-- untrusted note, never as the description of what will happen; effect is.
CREATE TABLE pending_action (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id    UUID        NOT NULL REFERENCES api_key (id) ON DELETE CASCADE,
    user_id       UUID        NOT NULL REFERENCES ocidex_user (id) ON DELETE CASCADE,
    namespace_id  UUID        NOT NULL REFERENCES namespace (id) ON DELETE CASCADE,
    capability    TEXT        NOT NULL,
    method        TEXT        NOT NULL,
    path          TEXT        NOT NULL,
    body          BYTEA       NOT NULL DEFAULT ''::bytea,
    effect        TEXT        NOT NULL,
    reason        TEXT,
    agent_label   TEXT,
    status        TEXT        NOT NULL DEFAULT 'pending',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    decided_by    UUID        REFERENCES ocidex_user (id) ON DELETE SET NULL,
    decided_at    TIMESTAMPTZ,
    executed_at   TIMESTAMPTZ,
    result_status INT,
    result_body   TEXT,
    CONSTRAINT pending_action_status_known
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'executed', 'failed'))
);

CREATE INDEX idx_pending_action_namespace_status ON pending_action (namespace_id, status);
CREATE INDEX idx_pending_action_user ON pending_action (user_id, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS pending_action;
ALTER TABLE api_key
    DROP CONSTRAINT IF EXISTS api_key_approval_within_ceiling,
    DROP COLUMN IF EXISTS approval_required;
