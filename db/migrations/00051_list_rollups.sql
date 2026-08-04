-- Precomputed rollups for the components, licenses, and vulnerabilities list
-- pages (ocidex-ckv.2).
--
-- Those three endpoints aggregated the whole 10.9M-row component table on every
-- request. The Components query alone measured 53 seconds with a 65 MB
-- external-merge spill against a 30 second HTTP timeout, so the pages usually
-- failed outright. The aggregated results are tiny — 121k, 10k, and 3.2k rows
-- respectively — and change only on ingest, so they are computed out of band.
--
-- Every rollup carries registry_id and is grouped by it. sbom_visible() is a
-- function of the registry alone, so a viewer's subset of rows can be summed at
-- read time and still be exact. Counts that decompose over registries are
-- stored as integers (an SBOM belongs to exactly one registry, so sbom_count
-- sums without double counting); counts that need DISTINCT across registries
-- keep their sets in arrays and are re-counted at read time.
--
-- The tables are seeded here so the list pages are never served from an empty
-- rollup between the migration and the first refresher pass.

-- +goose Up

-- One row per (registry, package identity). versions keeps NULL as an element
-- so readers can distinguish "no version recorded" from the empty string, which
-- the search and stats queries treat differently.
CREATE TABLE component_rollup (
    registry_id UUID REFERENCES registry (id) ON DELETE CASCADE,
    type        TEXT   NOT NULL,
    name        TEXT   NOT NULL,
    group_name  TEXT,
    purl_types  TEXT[] NOT NULL DEFAULT '{}',
    versions    TEXT[] NOT NULL DEFAULT '{}',
    sbom_count  BIGINT NOT NULL
);

COMMENT ON COLUMN component_rollup.purl_types IS
    'Distinct purl type prefixes seen for this identity. A purl_type filter selects the whole group, so for the rare identity that spans two ecosystems the filtered version/sbom counts cover both.';

-- Distinct (license, registry, component identity) triples. The identity is
-- pre-joined into one text key because the read query only needs to count
-- distinct identities, and counting one text column is far cheaper than
-- counting a four-column row constructor.
CREATE TABLE license_rollup (
    license_id   UUID NOT NULL REFERENCES license (id) ON DELETE CASCADE,
    registry_id  UUID REFERENCES registry (id) ON DELETE CASCADE,
    identity_key TEXT NOT NULL
);

CREATE INDEX idx_license_rollup_license ON license_rollup (license_id);

-- One row per (canonical vulnerability, registry). purls is a set because the
-- same package can be affected in several registries and the list reports a
-- distinct purl count.
CREATE TABLE vuln_rollup (
    canonical_id TEXT   NOT NULL,
    registry_id  UUID REFERENCES registry (id) ON DELETE CASCADE,
    sbom_count   BIGINT NOT NULL,
    purls        TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_vuln_rollup_canonical ON vuln_rollup (canonical_id);

INSERT INTO component_rollup (registry_id, type, name, group_name, purl_types, versions, sbom_count)
SELECT s.registry_id, c.type, c.name, c.group_name,
       COALESCE(array_agg(DISTINCT split_part(replace(c.purl, 'pkg:', ''), '/', 1))
                FILTER (WHERE c.purl IS NOT NULL), '{}')::text[],
       array_agg(DISTINCT c.version)::text[],
       count(DISTINCT c.sbom_id)::bigint
FROM component c
JOIN sbom s ON s.id = c.sbom_id
GROUP BY s.registry_id, c.type, c.name, c.group_name;

INSERT INTO license_rollup (license_id, registry_id, identity_key)
SELECT DISTINCT cl.license_id, s.registry_id,
       c.name || E'\x1f' || COALESCE(c.group_name, '') || E'\x1f' || COALESCE(c.version, '') || E'\x1f' || c.type
FROM component_license cl
JOIN component c ON c.id = cl.component_id
JOIN sbom s ON s.id = c.sbom_id;

INSERT INTO vuln_rollup (canonical_id, registry_id, sbom_count, purls)
SELECT v.canonical_id, s.registry_id,
       count(DISTINCT comp.sbom_id)::bigint,
       array_agg(DISTINCT pv.purl)::text[]
FROM vulnerability v
JOIN package_vulnerability pv ON pv.vulnerability_id = v.id
JOIN component comp ON comp.purl = pv.purl
JOIN sbom s ON s.id = comp.sbom_id
WHERE v.canonical_id <> '' AND comp.purl IS NOT NULL
GROUP BY v.canonical_id, s.registry_id;

-- +goose Down
DROP TABLE IF EXISTS vuln_rollup;
DROP TABLE IF EXISTS license_rollup;
DROP TABLE IF EXISTS component_rollup;
