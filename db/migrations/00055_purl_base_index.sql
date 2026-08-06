-- +goose NO TRANSACTION
-- Index backing the artifact-relationship join (ADR-041, ocidex-rj4.2).
--
-- ADR-041 R1 reuses componentKey() from internal/service/changelog.go, whose
-- purl branch is normalizeComponentPurl(): split on '?' first (qualifiers follow
-- the version in purl format), then truncate at '@'. The leading part of that —
-- the purl BASE, before identity qualifiers are re-appended — is expressible in
-- SQL, and it is what the relationship queries join on:
--
--     split_part(split_part(purl, '?', 1), '@', 1)
--
-- Note the argument order mirrors the Go: '?' before '@'. Reversing them breaks
-- purls that carry qualifiers but no version (pkg:golang/foo?arch=amd64), which
-- would otherwise keep their whole qualifier string in the "base".
--
-- This is deliberately a SUPERSET match: two components sharing a base but
-- differing in identity qualifiers (e.g. arch) both survive the join, and the
-- service filters them with the real componentKey(). Per ADR-041's indexing
-- caveat, the full normalized key cannot be indexed — qualifier filtering and
-- sorting live in Go — so the split is coarse-in-SQL, exact-in-Go.
--
-- idx_component_purl (raw purl btree) cannot serve this: an equality test on an
-- expression is not an equality test on the column, and a LIKE 'base%' rewrite
-- would need C collation or text_pattern_ops to be sargable at all.

-- +goose Up

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_purl_base
    ON component ((split_part(split_part(purl, '?', 1), '@', 1)))
    WHERE purl IS NOT NULL;

-- artifact is small enough that a seq scan is fine today, but the relationship
-- queries join on the same expression from both sides; indexing it keeps the
-- plan symmetric and costs almost nothing at this table's size.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifact_purl_base
    ON artifact ((split_part(split_part(purl, '?', 1), '@', 1)))
    WHERE purl IS NOT NULL;

-- The tuple fallback (ADR-019 Rule 2, components with no purl) joins on
-- (type, name, group_name). idx_component_name_group covers (name, group_name)
-- only, leaving type as a heap recheck; this makes the whole key index-resolvable.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_component_type_name_group
    ON component (type, name, group_name) WHERE purl IS NULL;

-- +goose Down

DROP INDEX CONCURRENTLY IF EXISTS idx_component_purl_base;
DROP INDEX CONCURRENTLY IF EXISTS idx_artifact_purl_base;
DROP INDEX CONCURRENTLY IF EXISTS idx_component_type_name_group;
