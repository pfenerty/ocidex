-- +goose Up
CREATE TABLE vuln_ecosystem_state (
    ecosystem        TEXT        PRIMARY KEY,
    last_modified_at TIMESTAMPTZ NOT NULL,
    checked_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS vuln_ecosystem_state;
