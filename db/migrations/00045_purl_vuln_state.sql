-- +goose Up
CREATE TABLE purl_vuln_state (
    purl       TEXT        PRIMARY KEY,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS purl_vuln_state;
