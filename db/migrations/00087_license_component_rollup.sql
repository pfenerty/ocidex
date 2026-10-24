-- +goose Up
-- license_component_rollup backs GET /api/v1/licenses/{id}/components
-- (ocidex-zbe5). That route aggregated every component carrying the license per
-- request, ~9.6s p95 at 10k SBOMs. This holds one row per (license, namespace,
-- distinct component) with its lowest-id component as the representative, so
-- the route reads a row per distinct component instead. RollupRefresher keeps
-- it current. The seeding INSERT is licenseComponentRollupAggregate in
-- internal/repository/rollup_refresh.go and must stay identical to it.
CREATE TABLE license_component_rollup (
    license_id    UUID    NOT NULL REFERENCES license(id) ON DELETE CASCADE,
    namespace_id  UUID    NOT NULL REFERENCES namespace(id) ON DELETE CASCADE,
    component_id  UUID    NOT NULL,
    sbom_id       UUID    NOT NULL,
    type          TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    group_name    TEXT,
    version       TEXT,
    purl          TEXT,
    version_major INTEGER,
    version_minor INTEGER,
    version_patch INTEGER
);
CREATE INDEX idx_license_component_rollup_license ON license_component_rollup (license_id, namespace_id);

INSERT INTO license_component_rollup
SELECT DISTINCT ON (cl.license_id, s.namespace_id, c.name, COALESCE(c.group_name, ''), COALESCE(c.version, ''), c.type)
       cl.license_id, s.namespace_id, c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
       c.version_major, c.version_minor, c.version_patch
FROM component_license cl
JOIN component c ON c.id = cl.component_id
JOIN sbom s ON s.id = c.sbom_id
ORDER BY cl.license_id, s.namespace_id, c.name, COALESCE(c.group_name, ''), COALESCE(c.version, ''), c.type, c.id;

-- +goose Down
DROP TABLE IF EXISTS license_component_rollup;
