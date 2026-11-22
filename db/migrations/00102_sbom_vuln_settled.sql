-- +goose Up

-- Every surface that headlines an artifact's or a version's findings reads
-- them from sbom_vuln_rollup, which a refresh pass rebuilds every 15 minutes
-- (RollupRefreshInterval). Counting some of them live instead meant that after
-- a rescan the artifact tile and the /artifacts row disagreed for up to a
-- refresh interval.
--
-- The rollup has a row only for an SBOM with findings, so "no row" is "no
-- findings" or "not scanned" (ADR-044). An SBOM matched long enough ago that a
-- refresh has certainly caught up, two intervals, can be called clean; one
-- matched more recently may have findings the rollup has not picked up yet.
-- This is that test, shared so every surface waits the same time.
-- +goose StatementBegin
CREATE FUNCTION sbom_vuln_settled(s_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM sbom_vuln_match m
    WHERE m.sbom_id = s_id AND m.matched_at < now() - interval '30 minutes')
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS sbom_vuln_settled(UUID);
