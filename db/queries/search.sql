-- name: GetSBOMByDigest :one
SELECT id FROM sbom WHERE digest = $1;

-- name: GetSBOM :one
-- source_kind comes from the owning source so enrichers can tell an OCI-backed
-- SBOM from an uploaded one without a second round-trip (ADR-039). It is '' for
-- an SBOM with no source.
SELECT s.id, s.serial_number, s.spec_version, s.version, s.artifact_id, s.subject_version,
       s.digest, s.created_at, s.namespace_id, s.source_id, s.index_digest,
       COALESCE(src.kind, '')::text AS source_kind
FROM sbom s
LEFT JOIN source src ON src.id = s.source_id
WHERE s.id = $1;

-- name: GetSBOMRef :one
-- Lightweight SBOM lookup for building a SBOMRef: joins enrichments to get
-- architecture and build_date without fetching the raw BOM.
SELECT s.id, s.subject_version, s.created_at,
       COALESCE(e.data->>'architecture', u.data->>'architecture') AS architecture,
       COALESCE(
           (e.data->>'created')::timestamptz,
           (u.data->>'created')::timestamptz
       ) AS build_date
FROM sbom s
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user' AND u.status = 'success'
WHERE s.id = $1;

-- name: GetSBOMRaw :one
SELECT raw_bom
FROM sbom
WHERE id = $1;

-- name: IsSBOMVisible :one
SELECT sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean) AS visible
FROM sbom s WHERE s.id = $1;

-- name: IsArtifactVisible :one
SELECT artifact_visible($1, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean) AS visible;

-- name: ListSBOMs :many
-- Keyset pagination on (created_at DESC, id DESC); backed by idx_sbom_created_at_id.
-- The caller fetches row_limit+1 to detect whether a further page exists.
SELECT s.id, s.serial_number, s.spec_version, s.version, s.artifact_id, s.subject_version, s.digest, s.created_at
FROM sbom s
WHERE (sqlc.narg('serial_number')::text IS NULL OR s.serial_number = sqlc.narg('serial_number'))
  AND (sqlc.narg('digest')::text IS NULL OR s.digest = sqlc.narg('digest'))
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (s.created_at, s.id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY s.created_at DESC, s.id DESC
LIMIT @row_limit;

-- name: ListOwnedActivity :many
-- "Recent activity" for a user workspace is the ingest stream: every SBOM that
-- landed in a namespace this user owns, newest first (ocidex-998g.2).
--
-- This is the ownership path, not the visibility path — an SBOM ingested into
-- somebody else's public namespace is not the caller's activity. Unlike the
-- other me-scoped collections there is no visibility-path twin to share, so no
-- owned_only switch: owner_id is the only rule this query has.
--
-- Rows are appended at the head of an immutable ordering, so pagination is
-- keyset on (created_at DESC, id DESC) per ADR-043 rule 2. The caller fetches
-- row_limit+1 to detect whether a further page exists.
SELECT s.id, s.digest, s.subject_version, s.created_at,
       n.id AS namespace_id,
       n.name AS namespace_name,
       src.id AS source_id,
       src.name AS source_name,
       src.kind AS source_kind,
       a.id AS artifact_id,
       a.name AS artifact_name,
       a.type AS artifact_type
FROM sbom s
JOIN namespace n ON n.id = s.namespace_id
LEFT JOIN source src ON src.id = s.source_id
LEFT JOIN artifact a ON a.id = s.artifact_id
WHERE n.owner_id = sqlc.arg('owner_id')::uuid
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (s.created_at, s.id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY s.created_at DESC, s.id DESC
LIMIT @row_limit;

-- name: ListSBOMsByDigest :many
SELECT s.id, s.serial_number, s.spec_version, s.version, s.artifact_id, s.subject_version, s.digest, s.created_at,
       COUNT(*) OVER() AS total_count
FROM sbom s
WHERE s.digest = $1
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY s.created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: SearchComponents :many
SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
       COUNT(*) OVER() AS total_count
FROM component c
-- ADR-042 R6: purl is the cross-SBOM key for a component, since a component row
-- is SBOM-scoped and has no stable identity of its own. It is matched exactly,
-- not by prefix, so a link built from one row's purl returns every SBOM
-- carrying that same package version. The API requires name or purl, so the
-- pair of NULLs that would scan the whole table never reaches here.
WHERE (sqlc.narg('name')::text IS NULL OR c.name = sqlc.narg('name'))
  AND (sqlc.narg('purl')::text IS NULL OR c.purl = sqlc.narg('purl'))
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('version')::text IS NULL OR c.version = sqlc.narg('version'))
  AND EXISTS (
    SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
      AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
  )
ORDER BY c.version_major DESC NULLS LAST,
         c.version_minor DESC NULLS LAST,
         c.version_patch DESC NULLS LAST
LIMIT @row_limit OFFSET @row_offset;

-- name: GetComponent :one
SELECT id, sbom_id, parent_id, bom_ref, type, name, group_name,
       version, purl, cpe, description, scope, publisher, copyright, found_by,
       source_purl, source_package, layer_id
FROM component
WHERE id = $1;

-- name: ListComponentHashes :many
SELECT algorithm, value
FROM component_hash
WHERE component_id = $1;

-- name: ListComponentLicenses :many
SELECT l.id, l.spdx_id, l.name, l.url
FROM license l
JOIN component_license cl ON cl.license_id = l.id
WHERE cl.component_id = $1;

-- name: ListComponentExtRefs :many
SELECT type, url, comment
FROM external_reference
WHERE component_id = $1;

-- name: ListLicenses :many
-- Reads license_rollup rather than joining component_license to component: the
-- old plan did 266k random heap lookups on component_pkey per request
-- (ocidex-ckv.2). identity_key is the same (name, group, version, type) tuple
-- the old COUNT(DISTINCT (...)) built, pre-joined into one text column.
-- The visibility test lives in the JOIN condition, not the WHERE clause, so a
-- license whose only components sit in namespaces the viewer cannot see still
-- appears rather than vanishing from the list.
--
-- Such a license now counts 0, where the old query counted 1. That is a fix,
-- not a regression: COUNT(DISTINCT (c.name, COALESCE(c.group_name,''), ...))
-- over a non-matching LEFT JOIN row yielded the composite (NULL,'','',NULL),
-- which is not the NULL row, so COUNT counted it. Every license with no
-- visible components reported exactly one. 14 licenses in dev were affected.
SELECT l.id, l.spdx_id, l.name, l.url,
       COUNT(DISTINCT lr.identity_key) AS component_count,
       COUNT(*) OVER() AS total_count
FROM license l
LEFT JOIN license_rollup lr ON lr.license_id = l.id
  AND (lr.namespace_id IN (
        SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)))
-- Substring matches, both of them. These were an exact `=` on spdx_id and a
-- wildcard-free ILIKE on name, so "Filter by name…" only ever matched a reader
-- who typed the whole license name — every prefix on the way to "Apache-2.0"
-- reported that no such license exists. Tolerable behind a submit button;
-- actively misleading now that the box filters as you type (ocidex-ag4q.31).
WHERE (sqlc.narg('spdx_id')::text IS NULL OR l.spdx_id ILIKE '%' || sqlc.narg('spdx_id')::text || '%')
  AND (sqlc.narg('name')::text IS NULL OR l.name ILIKE '%' || sqlc.narg('name')::text || '%')
  AND (sqlc.narg('category')::text IS NULL OR license_category(l.spdx_id) = sqlc.narg('category')::text)
GROUP BY l.id, l.spdx_id, l.name, l.url
ORDER BY component_count DESC, l.name
LIMIT @row_limit OFFSET @row_offset;

-- name: ListComponentsByLicense :many
WITH ranked AS (
    SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
           c.version_major, c.version_minor, c.version_patch,
           ROW_NUMBER() OVER (
               PARTITION BY c.name, COALESCE(c.group_name, ''), COALESCE(c.version, ''), c.type
               ORDER BY c.id
           ) AS rn
    FROM component c
    JOIN component_license cl ON cl.component_id = c.id
    WHERE cl.license_id = @license_id
      AND EXISTS (
        SELECT 1 FROM sbom s WHERE s.id = c.sbom_id
          AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
      )
)
SELECT id, sbom_id, type, name, group_name, version, purl,
       COUNT(*) OVER() AS total_count
FROM ranked
WHERE rn = 1
ORDER BY name,
         version_major DESC NULLS LAST,
         version_minor DESC NULLS LAST,
         version_patch DESC NULLS LAST
LIMIT @row_limit OFFSET @row_offset;

-- name: LicenseSummaryByArtifact :many
SELECT l.id, l.spdx_id, l.name, l.url, COUNT(DISTINCT cl.component_id) AS component_count
FROM sbom s
JOIN component c ON c.sbom_id = s.id
JOIN component_license cl ON cl.component_id = c.id
JOIN license l ON l.id = cl.license_id
WHERE s.artifact_id = @artifact_id
  AND s.id = (
    SELECT id FROM sbom WHERE artifact_id = @artifact_id ORDER BY created_at DESC LIMIT 1
  )
GROUP BY l.id, l.spdx_id, l.name, l.url
ORDER BY component_count DESC, l.name;

-- name: ListDependenciesBySBOM :many
SELECT ref, depends_on
FROM dependency
WHERE sbom_id = $1
ORDER BY ref, depends_on;

-- name: GetSBOMMetadataBomRef :one
-- Returns metadata.component.bom-ref from the raw CycloneDX BOM, or NULL if absent.
SELECT raw_bom->'metadata'->'component'->>'bom-ref' AS bom_ref
FROM sbom
WHERE id = $1;

-- name: CountSBOMComponents :one
SELECT COUNT(*) FROM component WHERE sbom_id = $1;

-- name: CountSBOMPackages :one
-- Counts package components (excludes file entries), matching what the packages
-- tab displays.
SELECT COUNT(*) FROM component WHERE sbom_id = $1 AND type != 'file';

-- name: ListSBOMComponents :many
SELECT id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = $1
ORDER BY name, group_name;

-- name: ListSBOMComponentsPage :many
-- Keyset variant of ListSBOMComponents for the HTTP endpoint. Files are
-- excluded: the packages tab (the only consumer) shows packages only, and
-- including file components — which can vastly outnumber packages — would fill
-- whole pages with rows the client then filters out, leaving the list empty.
-- Ordered by (name, group_name, id) with NULL group_name folded to '' so the
-- cursor tuple comparison matches the ORDER BY. Access is gated by the service
-- before this runs. The caller fetches row_limit+1 to detect a further page.
SELECT id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = @sbom_id
  AND type != 'file'
  AND (
    NOT sqlc.narg('has_cursor')::boolean
    OR (name, COALESCE(group_name, ''), id) > (sqlc.narg('cursor_name')::text, sqlc.narg('cursor_group')::text, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY name, COALESCE(group_name, ''), id
LIMIT @row_limit;

-- name: ListSBOMPackages :many
SELECT id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = $1 AND type != 'file'
ORDER BY name, group_name;

-- name: ListSBOMPackagesBySBOMIDs :many
-- Batched variant of ListSBOMPackages: fetches packages for many SBOMs in one
-- round-trip (avoids the per-version N+1 in changelog generation). The caller
-- groups the rows by sbom_id.
SELECT sbom_id, id, bom_ref, type, name, group_name, version, purl
FROM component
WHERE sbom_id = ANY(@sbom_ids::uuid[]) AND type != 'file'
ORDER BY sbom_id, name, group_name;

-- name: ListComponentPurlTypes :many
-- Reads component_rollup (ocidex-ckv.2). This populates the filter dropdown on
-- the same page as SearchDistinctComponents, so leaving it scanning all 10.9M
-- component rows for a DISTINCT would have kept that page slow regardless.
-- The rollup already stores the split_part result per identity.
SELECT DISTINCT p.purl_type::text AS purl_type
FROM component_rollup r
CROSS JOIN LATERAL unnest(r.purl_types) AS p(purl_type)
WHERE (r.namespace_id IN (
        SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)))
ORDER BY 1
-- Safety cap: purl types are a small, fixed vocabulary; bound the scan.
LIMIT 200;

-- name: SearchDistinctComponents :many
-- Reads component_rollup rather than the component table: aggregating 10.9M raw
-- rows per request took ~53s against a 30s HTTP timeout (ocidex-ckv.2).
--
-- The rollup is per-namespace, so a row set restricted by sbom_visible() must be
-- re-aggregated here. version_count and purl_types use COUNT/string_agg
-- DISTINCT and so are immune to the row multiplication the two unnests cause.
-- SUM is not, hence the ordinality filter: it charges each rollup row's
-- sbom_count exactly once, on the single expanded row where both unnests are at
-- their first element. COALESCE covers an empty array, where the LEFT JOIN
-- yields one row with a NULL ordinal.
SELECT r.name, r.group_name, r.type,
       COALESCE(string_agg(DISTINCT p.purl_type, ',' ORDER BY p.purl_type), '') AS purl_types,
       COUNT(DISTINCT v.version) AS version_count,
       COALESCE(SUM(r.sbom_count) FILTER (WHERE COALESCE(v.ord, 1) = 1 AND COALESCE(p.ord, 1) = 1), 0)::bigint AS sbom_count,
       -- Severity counts (ocidex-unn8.10) come out of the rollup for the same
       -- ~53s reason as sbom_count. MAX, not SUM, across the visible namespaces:
       -- a CVE affecting this package is a property of the package, so summing
       -- the per-namespace rows would report it once per namespace that happens
       -- to hold the package. MAX reports the worst any one namespace sees --
       -- a lower bound when two namespaces hold disjoint version sets, which is
       -- the safe direction to be wrong in for an ordering key. It is also
       -- immune to the unnest row multiplication, so it needs no ordinality
       -- filter.
       --
       -- Zero is a real zero here, unlike the artifact and version lists:
       -- component_rollup has a row for every package identity, so there is no
       -- "never scanned" state to confuse it with (ADR-044 does not apply).
       MAX(r.critical)::bigint AS critical,
       MAX(r.high)::bigint     AS high,
       MAX(r.medium)::bigint   AS medium,
       MAX(r.low)::bigint      AS low,
       MAX(r.unknown)::bigint  AS unknown,
       COUNT(*) OVER() AS total_count
FROM component_rollup r
LEFT JOIN LATERAL unnest(r.versions) WITH ORDINALITY AS v(version, ord) ON true
LEFT JOIN LATERAL unnest(r.purl_types) WITH ORDINALITY AS p(purl_type, ord) ON true
WHERE (sqlc.narg('name')::text IS NULL OR r.name ILIKE sqlc.narg('name'))
  AND (sqlc.narg('group_name')::text IS NULL OR r.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('type')::text IS NULL OR r.type = sqlc.narg('type'))
  AND (sqlc.narg('purl_type')::text IS NULL OR sqlc.narg('purl_type')::text = ANY(r.purl_types))
  AND (r.namespace_id IN (
        SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)))
GROUP BY r.name, r.group_name, r.type
ORDER BY
  -- 'severity' needs five keys rather than one: a single total would rank a
  -- package with 40 lows above one with a critical. Ranked lexicographically,
  -- worst severity first, the way the /artifacts list orders. The keys collapse
  -- to NULL under any other sort, so every row ties and the CASE below decides.
  CASE WHEN @sort_by::text = 'severity' THEN MAX(r.critical) END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
  CASE WHEN @sort_by::text = 'severity' THEN MAX(r.high)     END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
  CASE WHEN @sort_by::text = 'severity' THEN MAX(r.medium)   END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
  CASE WHEN @sort_by::text = 'severity' THEN MAX(r.low)      END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
  CASE WHEN @sort_by::text = 'severity' THEN MAX(r.unknown)  END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
  CASE @sort_by::text
    WHEN 'version_count' THEN COUNT(DISTINCT v.version)
    WHEN 'sbom_count' THEN COALESCE(SUM(r.sbom_count) FILTER (WHERE COALESCE(v.ord, 1) = 1 AND COALESCE(p.ord, 1) = 1), 0)
  END * CASE @sort_dir::text WHEN 'asc' THEN 1 ELSE -1 END ASC NULLS LAST,
  r.name, r.group_name
LIMIT @row_limit OFFSET @row_offset;

-- name: GetComponentVersions :many
SELECT c.id, c.sbom_id, c.type, c.name, c.group_name, c.version, c.purl,
       s.artifact_id, s.subject_version, s.digest AS sbom_digest,
       a.name AS artifact_name,
       s.created_at AS sbom_created_at,
       COALESCE(e.data->>'architecture', u.data->>'architecture') AS architecture
FROM component c
JOIN sbom s ON s.id = c.sbom_id
LEFT JOIN artifact a ON a.id = s.artifact_id
LEFT JOIN enrichment e ON e.sbom_id = s.id AND e.enricher_name = 'oci-metadata' AND e.status = 'success'
LEFT JOIN enrichment u ON u.sbom_id = s.id AND u.enricher_name = 'user' AND u.status = 'success'
WHERE c.name = @name
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('version')::text IS NULL OR c.version = sqlc.narg('version'))
  AND (sqlc.narg('type')::text IS NULL OR c.type = sqlc.narg('type'))
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean)
ORDER BY c.version_major DESC NULLS LAST,
         c.version_minor DESC NULLS LAST,
         c.version_patch DESC NULLS LAST,
         s.created_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: CountComponentVersions :one
-- The total for GetComponentVersions, deliberately NOT a COUNT(*) OVER() inside
-- that query. The window function is the convention elsewhere in this file, but
-- it only pays where the page and the count cost the same scan. Here the page
-- query carries three LEFT JOINs (artifact plus two enrichment lookups) and a
-- four-key sort purely to shape the rows it returns; a window count would drag
-- every matching row through all of that just to discard it. The most-used
-- component names have thousands of rows, which is what made the unpaginated
-- version time out at 30s (ocidex-ag4q.7).
--
-- Counting needs only the visibility join, so it stays on
-- idx_component_name_group.
--
-- It also carries the two corpus-wide figures a summary band needs, because
-- both are answers about the whole result set and the page query only ever sees
-- one window of it (ocidex-ag4q.35). Deriving them client-side from a page
-- would report "3 versions" for a component with 300 — worse than saying
-- nothing. They ride along here rather than in a third query: the scan and the
-- filters are identical, so the only added cost is the DISTINCT aggregation.
SELECT COUNT(*) AS total,
       COUNT(DISTINCT c.version) AS version_count,
       COUNT(DISTINCT s.artifact_id) AS artifact_count
FROM component c
JOIN sbom s ON s.id = c.sbom_id
WHERE c.name = @name
  AND (sqlc.narg('group_name')::text IS NULL OR c.group_name = sqlc.narg('group_name'))
  AND (sqlc.narg('version')::text IS NULL OR c.version = sqlc.narg('version'))
  AND (sqlc.narg('type')::text IS NULL OR c.type = sqlc.narg('type'))
  AND sbom_visible(s.namespace_id, sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean);
