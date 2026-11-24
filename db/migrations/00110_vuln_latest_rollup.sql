-- Which artifacts' latest tags still carry each vulnerability (ocidex-jdk1).
--
-- The Vulnerabilities list counted affected SBOMs, which counts every
-- historical SBOM (1,018 for some CVEs): a number that only grows. One row
-- here per (canonical vulnerability, namespace, artifact) whose newest tag in
-- that namespace carries it, ordered the way artifact_headline_sbom orders
-- versions, so the list can count distinct artifacts over the namespaces a
-- viewer sees. Per namespace rather than per viewer, so it can be rolled up:
-- an artifact in two visible namespaces counts when either namespace's newest
-- tag is affected.
--
-- fix_available_since is the earliest any matching mapping on that tag was
-- reported fixed (00109), so the list can sort by how long a fix has been
-- out for what is actually shipped.
--
-- The seed below is the same query as vulnLatestRollupAggregate in
-- internal/repository/rollup_refresh.go; a test holds them equal.

-- +goose Up
CREATE TABLE vuln_latest_rollup (
    canonical_id        TEXT        NOT NULL,
    namespace_id        UUID        REFERENCES namespace (id) ON DELETE CASCADE,
    artifact_id         UUID        NOT NULL REFERENCES artifact (id) ON DELETE CASCADE,
    fix_available_since TIMESTAMPTZ
);

CREATE INDEX idx_vuln_latest_rollup_canonical ON vuln_latest_rollup (canonical_id);

INSERT INTO vuln_latest_rollup (canonical_id, namespace_id, artifact_id, fix_available_since)
WITH latest AS (
    SELECT DISTINCT ON (s.artifact_id, s.namespace_id) s.id, s.artifact_id, s.namespace_id
    FROM sbom s
    WHERE s.artifact_id IS NOT NULL
    ORDER BY s.artifact_id, s.namespace_id,
             s.version_prerelease,
             s.version_major DESC NULLS LAST,
             s.version_minor DESC NULLS LAST,
             s.version_patch DESC NULLS LAST,
             s.version_variant <> '',
             s.version_variant,
             sbom_arch_rank(sbom_architecture(s.id)),
             s.created_at DESC, s.id DESC
), scope AS (
    SELECT DISTINCT l.namespace_id, l.artifact_id, c1.purl::text AS match_purl, COALESCE(c1.go_symbol_set_id, 0) AS go_symbol_set_id
    FROM latest l
    JOIN component c1 ON c1.sbom_id = l.id
    WHERE c1.purl IS NOT NULL
    UNION
    SELECT DISTINCT l.namespace_id, l.artifact_id, c2.source_purl::text AS match_purl, 0::bigint AS go_symbol_set_id
    FROM latest l
    JOIN component c2 ON c2.sbom_id = l.id
    WHERE c2.source_purl IS NOT NULL
)
SELECT v.canonical_id, sc.namespace_id, sc.artifact_id,
       min(pv.fix_available_since) AS fix_available_since
FROM scope sc
JOIN package_vulnerability pv ON pv.purl = sc.match_purl AND pv.go_symbol_set_id = sc.go_symbol_set_id
JOIN vulnerability v ON v.id = pv.vulnerability_id
WHERE v.canonical_id <> ''
GROUP BY v.canonical_id, sc.namespace_id, sc.artifact_id;

-- +goose Down
DROP TABLE IF EXISTS vuln_latest_rollup;
