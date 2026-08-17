-- Ranking formula for the public discovery surface (ocidex-q1z7.1).
--
-- The discovery page ranks artifacts by three signals that already exist in the
-- schema — no telemetry is collected or needed:
--
--   usage_count    how many other SBOMs contain this artifact (ADR-041 usages)
--   version_count  how many distinct versions have been ingested
--   last_activity  when the most recent SBOM for it landed
--
-- The weighting lives here, in one function, rather than inline in each query:
-- the discovery queries select different row sets but must agree on what
-- "notable" means, and a formula copied into four ORDER BY clauses drifts the
-- first time one of them is tuned.
--
-- Shape of the formula:
--
--   * Both counts are log-damped. Usage counts are heavy-tailed — a handful of
--     base images appear in nearly every SBOM — and a linear term lets those few
--     rows own every slot on the page permanently, which makes the ranking
--     useless as *discovery*.
--   * Usage outweighs version breadth 3:1. "Lots of other things depend on this"
--     is the signal a visitor came for; "this has had many releases" is a weaker
--     proxy that also rewards noisy tag schemes.
--   * Recency is a bounded bonus (0..2 over a 30-day half-life-ish decay), not a
--     multiplier. It surfaces freshly ingested content on a catalog that is still
--     small, but it can never demote a genuinely widely used artifact below a
--     one-off upload from this morning.
--
-- STABLE, not IMMUTABLE: the recency term reads now(). That is also why the
-- function cannot be used in an index — it is only ever evaluated over the
-- already-narrowed candidate sets of the discovery queries, which the stats
-- warmer computes out of band.

-- +goose Up

-- +goose StatementBegin
CREATE FUNCTION discovery_score(
    usage_count   BIGINT,
    version_count BIGINT,
    last_activity TIMESTAMPTZ
) RETURNS DOUBLE PRECISION
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT 3.0 * ln(1.0 + GREATEST(COALESCE(usage_count, 0), 0)::double precision)
         + 1.0 * ln(1.0 + GREATEST(COALESCE(version_count, 0), 0)::double precision)
         + CASE
               WHEN last_activity IS NULL THEN 0.0
               ELSE 2.0 * exp(
                   -GREATEST(EXTRACT(EPOCH FROM (now() - last_activity)), 0)::double precision
                   / 2592000.0
               )
           END
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION discovery_score(BIGINT, BIGINT, TIMESTAMPTZ) IS
    'Popularity ranking for the public discovery page: log-damped usage and version counts plus a bounded recency bonus. Single tuning point for every discovery query.';

-- +goose Down

DROP FUNCTION IF EXISTS discovery_score(BIGINT, BIGINT, TIMESTAMPTZ);
