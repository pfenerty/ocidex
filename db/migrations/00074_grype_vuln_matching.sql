-- Vulnerability matching moves from OSV's query API to the grype database
-- (ADR-049). The vuln-worker now matches whole SBOMs rather than querying purls,
-- so its bookkeeping is per SBOM and per database build:
--
--   * vuln_refresh_state.db_built_at — the grype build package_vulnerability was
--     last fully rebuilt from. A worker that opens a different build re-matches
--     everything; one that restarts on the same build does not.
--   * sbom_vuln_match — which build each SBOM was last matched against. An SBOM
--     with no row (newly ingested) or an older build is pending.
--
-- purl_vuln_state (00045) and vuln_ecosystem_state (00041) existed only to steer
-- incremental OSV querying and have no reader left.

-- +goose Up
ALTER TABLE vuln_refresh_state ADD COLUMN db_built_at TIMESTAMPTZ;

CREATE TABLE sbom_vuln_match (
    sbom_id     UUID        PRIMARY KEY REFERENCES sbom (id) ON DELETE CASCADE,
    db_built_at TIMESTAMPTZ NOT NULL,
    matched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TABLE IF EXISTS purl_vuln_state;
DROP TABLE IF EXISTS vuln_ecosystem_state;

-- +goose Down
CREATE TABLE vuln_ecosystem_state (
    ecosystem        TEXT        PRIMARY KEY,
    last_modified_at TIMESTAMPTZ NOT NULL,
    checked_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE purl_vuln_state (
    purl       TEXT        PRIMARY KEY,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
DROP TABLE IF EXISTS sbom_vuln_match;
ALTER TABLE vuln_refresh_state DROP COLUMN IF EXISTS db_built_at;
