-- Dashboard stats from the rollups (ocidex-kf1p.5).
--
-- Four of the dashboard aggregates — the package and version growth timelines,
-- the license category breakdown and the vulnerability totals — still read the
-- 10.9M-row component table, and the stats warmer runs them every five minutes
-- for every visibility scope it keeps warm. Each run is a full scan of ~44 GB
-- that also evicts the request path's working set. The rollup pass already
-- scans component once; these columns let it carry what the timelines need, and
-- the other two stats move to license_rollup and vuln_rollup, which exist.
--
-- component_rollup.first_seen is appended after the severity columns on
-- purpose: SwapRollupSnapshots repopulates with a positional
-- `INSERT ... SELECT *`, so the live table's column order must match
-- componentRollupAggregate's select list (see 00064).

-- +goose Up

-- One row per (namespace, package identity, version), with the moment it was
-- first ingested there. The version timeline needs first-seen at version grain,
-- which component_rollup's versions array cannot carry. NULL versions stay
-- NULL, matching component_rollup.versions.
CREATE TABLE component_version_rollup (
    namespace_id UUID        NOT NULL REFERENCES namespace (id) ON DELETE CASCADE,
    type         TEXT        NOT NULL,
    name         TEXT        NOT NULL,
    group_name   TEXT,
    version      TEXT,
    first_seen   TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_component_version_rollup_namespace ON component_version_rollup (namespace_id);

ALTER TABLE component_rollup ADD COLUMN first_seen TIMESTAMPTZ;

COMMENT ON COLUMN component_rollup.first_seen IS
    'Earliest created_at of any SBOM in this namespace carrying this package identity. Backs the package growth timeline.';

-- component_rollup has carried no index since 00051: every read filters on
-- namespace_id, and the /components name box is a substring ILIKE.
CREATE INDEX idx_component_rollup_namespace ON component_rollup (namespace_id);
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX idx_component_rollup_name_trgm ON component_rollup USING gin (name gin_trgm_ops);

-- Seeded so the dashboard is not served from an empty table between this
-- migration and the first refresher pass. Must match
-- componentVersionRollupAggregate in internal/repository/rollup_refresh.go.
INSERT INTO component_version_rollup (namespace_id, type, name, group_name, version, first_seen)
SELECT s.namespace_id, c.type, c.name, c.group_name, c.version,
       min(s.created_at) AS first_seen
FROM component c
JOIN sbom s ON s.id = c.sbom_id
GROUP BY s.namespace_id, c.type, c.name, c.group_name, c.version;

-- Derived from the table just built rather than from component again: one
-- full scan in this migration, not two.
UPDATE component_rollup r
SET first_seen = v.first_seen
FROM (
    SELECT namespace_id, type, name, group_name, min(first_seen) AS first_seen
    FROM component_version_rollup
    GROUP BY namespace_id, type, name, group_name
) v
WHERE v.namespace_id = r.namespace_id
  AND v.type = r.type
  AND v.name = r.name
  AND v.group_name IS NOT DISTINCT FROM r.group_name;

-- +goose Down
DROP INDEX IF EXISTS idx_component_rollup_name_trgm;
DROP INDEX IF EXISTS idx_component_rollup_namespace;
ALTER TABLE component_rollup DROP COLUMN IF EXISTS first_seen;
DROP TABLE IF EXISTS component_version_rollup;
