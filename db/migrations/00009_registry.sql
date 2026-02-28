-- +goose Up
CREATE TABLE registry (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT        NOT NULL UNIQUE,
    type           TEXT        NOT NULL DEFAULT 'generic'
                               CHECK (type IN ('zot', 'harbor', 'docker', 'generic')),
    url            TEXT        NOT NULL,
    insecure       BOOLEAN     NOT NULL DEFAULT false,
    webhook_secret TEXT,
    enabled        BOOLEAN     NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS registry;
