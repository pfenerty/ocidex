-- +goose Up
-- The grype build each vulnerability row, reference and package mapping was last
-- written from (ADR-049, "Resumable re-match"). The vuln-worker writes each
-- SBOM's matches as it goes, stamped with the build it matched against, and
-- only once every SBOM has been matched against that build deletes what other
-- builds wrote. NULL marks a row written before stamping; the first completed
-- pass removes it.
ALTER TABLE vulnerability ADD COLUMN db_built_at TIMESTAMPTZ;
ALTER TABLE vulnerability_reference ADD COLUMN db_built_at TIMESTAMPTZ;
ALTER TABLE package_vulnerability ADD COLUMN db_built_at TIMESTAMPTZ;

-- vuln_severity_rank orders the stored severity labels, so two SBOMs' views of
-- one vulnerability merge to the more severe regardless of match order.
-- +goose StatementBegin
CREATE FUNCTION vuln_severity_rank(label TEXT) RETURNS INT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE label
        WHEN 'CRITICAL' THEN 4
        WHEN 'HIGH'     THEN 3
        WHEN 'MEDIUM'   THEN 2
        WHEN 'LOW'      THEN 1
        ELSE 0
    END
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS vuln_severity_rank(TEXT);
ALTER TABLE package_vulnerability DROP COLUMN IF EXISTS db_built_at;
ALTER TABLE vulnerability_reference DROP COLUMN IF EXISTS db_built_at;
ALTER TABLE vulnerability DROP COLUMN IF EXISTS db_built_at;
