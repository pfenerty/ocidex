-- Function symbols linked into Go binaries, for symbol-level vulnerability
-- matching and cross-SBOM correlation (ADR-050).
--
--   go_package     one row per import path ever seen (net/http, golang.org/x/net/http2, …)
--   go_symbol      one row per (import path, local name), names normalized to govulndb's
--                  convention; the empty name marks "import path present, no symbols"
--   go_symbol_set  the exact symbol list of one module within one binary, content-addressed
--                  by the sha256 of its sorted symbol ids, so an identical module build is
--                  stored once however many SBOMs contain it
--   component.go_symbol_set_id  which set a component (a module in a binary) links
--
-- Set membership is a sorted INTEGER[] with a GIN index rather than a junction
-- table: the same relation at about a tenth of the size (a large Go image links ~1M
-- symbols), still answering "which sets contain symbol X" by index
-- (symbol_ids @> ARRAY[x]). go_symbol_set_member exposes the junction shape.
--
-- package_vulnerability gains go_symbol_set_id: a symbol-level match result
-- belongs to (purl, symbol set), not to the purl alone — stdlib@1.18.2 in a
-- binary that links net/http.(*Server).Serve is affected by an advisory that the
-- same stdlib in another binary is not. 0 means "matched without symbols"
-- (module level); 0 rather than NULL keeps every read-side join an index
-- equality. Readers join on pv.go_symbol_set_id = COALESCE(c.go_symbol_set_id, 0).
-- sbom_vuln_rollup is re-seeded with the aggregate that join implies
-- (internal/repository/rollup_refresh.go, kept in step by
-- TestSBOMVulnRollupSeedMatchesTheRefreshAggregate).

-- +goose Up
CREATE TABLE go_package (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    import_path TEXT NOT NULL UNIQUE
);

CREATE TABLE go_symbol (
    id         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    package_id INTEGER NOT NULL REFERENCES go_package (id),
    name       TEXT    NOT NULL,
    UNIQUE (package_id, name)
);

CREATE TABLE go_symbol_set (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    digest       BYTEA     NOT NULL UNIQUE,
    symbol_ids   INTEGER[] NOT NULL,
    symbol_count INTEGER   NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_go_symbol_set_symbols ON go_symbol_set USING GIN (symbol_ids);

ALTER TABLE component ADD COLUMN go_symbol_set_id BIGINT REFERENCES go_symbol_set (id);
CREATE INDEX idx_component_go_symbol_set ON component (go_symbol_set_id) WHERE go_symbol_set_id IS NOT NULL;

CREATE VIEW go_symbol_set_member AS
SELECT s.id AS set_id, m.symbol_id
FROM go_symbol_set s, unnest(s.symbol_ids) AS m(symbol_id);

ALTER TABLE package_vulnerability ADD COLUMN go_symbol_set_id BIGINT NOT NULL DEFAULT 0;
ALTER TABLE package_vulnerability DROP CONSTRAINT package_vulnerability_pkey;
ALTER TABLE package_vulnerability ADD PRIMARY KEY (purl, go_symbol_set_id, vulnerability_id);

TRUNCATE sbom_vuln_rollup;
INSERT INTO sbom_vuln_rollup (sbom_id, namespace_id, critical, high, medium, low, unknown)
WITH scope AS (
    SELECT DISTINCT c1.sbom_id, c1.purl::text AS match_purl, COALESCE(c1.go_symbol_set_id, 0) AS go_symbol_set_id
    FROM component c1 WHERE c1.purl IS NOT NULL
    UNION
    SELECT DISTINCT c2.sbom_id, c2.source_purl::text AS match_purl, 0::bigint AS go_symbol_set_id
    FROM component c2 WHERE c2.source_purl IS NOT NULL
), findings AS (
    SELECT DISTINCT sc.sbom_id, v.canonical_id, v.severity
    FROM scope sc
    JOIN package_vulnerability pv ON pv.purl = sc.match_purl AND pv.go_symbol_set_id = sc.go_symbol_set_id
    JOIN vulnerability v ON v.id = pv.vulnerability_id
)
SELECT f.sbom_id, s.namespace_id,
       count(*) FILTER (WHERE f.severity = 'CRITICAL')::bigint AS critical,
       count(*) FILTER (WHERE f.severity = 'HIGH')::bigint     AS high,
       count(*) FILTER (WHERE f.severity = 'MEDIUM')::bigint   AS medium,
       count(*) FILTER (WHERE f.severity = 'LOW')::bigint      AS low,
       count(*) FILTER (WHERE f.severity IS NULL
                           OR f.severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))::bigint AS unknown
FROM findings f
JOIN sbom s ON s.id = f.sbom_id
GROUP BY f.sbom_id, s.namespace_id;

-- +goose Down
-- Symbol-scoped mappings have no representation in the old purl-keyed table; the
-- next full re-match rebuilds module-level ones. The rollup is rebuilt by the
-- rollup refresher.
DELETE FROM package_vulnerability WHERE go_symbol_set_id <> 0;
ALTER TABLE package_vulnerability DROP CONSTRAINT package_vulnerability_pkey;
ALTER TABLE package_vulnerability DROP COLUMN go_symbol_set_id;
ALTER TABLE package_vulnerability ADD PRIMARY KEY (purl, vulnerability_id);
DROP VIEW IF EXISTS go_symbol_set_member;
DROP INDEX IF EXISTS idx_component_go_symbol_set;
ALTER TABLE component DROP COLUMN IF EXISTS go_symbol_set_id;
DROP TABLE IF EXISTS go_symbol_set;
DROP TABLE IF EXISTS go_symbol;
DROP TABLE IF EXISTS go_package;
