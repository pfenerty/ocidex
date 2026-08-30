-- Registry is the oci_registry subtype of source (ADR-039): it holds discovery
-- config and trust policy only. Its id *is* the source id, which is also the
-- namespace id for registries created here. Name, owner and visibility live on
-- namespace and are joined back in on read so the API surface is unchanged.

-- name: CreateRegistry :one
-- Writes namespace, source and registry in one statement. Data-modifying CTEs
-- share a snapshot and FK triggers fire once at statement end, so the three
-- rows may reference each other.
--
-- When namespace_id is NULL the registry gets a namespace of its own named
-- after it, and all three rows share an id — the shape migration 00053 produced
-- for pre-existing registries. When namespace_id is supplied (the operator
-- defaulting an OCIDex namespace from the CR's K8s namespace) only source and
-- registry are written, and they share an id inside the existing namespace.
WITH new_id AS (
    SELECT gen_random_uuid() AS id
),
ns AS (
    INSERT INTO namespace (id, name, visibility)
    SELECT n.id, @name::text, @visibility::text
    FROM new_id n
    WHERE sqlc.narg('namespace_id')::uuid IS NULL
    RETURNING id
),
-- The owner of a namespace minted here is a member row, not a column
-- (ocidex-y0hg.4). It is written only on the mint path: supplying namespace_id
-- means joining a namespace that already has its own members, and an import
-- must not quietly make the importing user its owner.
--
-- A NULL owner_user_id leaves the namespace ownerless, which is what the
-- unattributed import paths have always produced.
ns_owner AS (
    INSERT INTO namespace_member (namespace_id, user_id, role)
    SELECT ns.id, sqlc.narg('owner_user_id')::uuid, 'owner'
    FROM ns
    WHERE sqlc.narg('owner_user_id')::uuid IS NOT NULL
    RETURNING user_id
),
target_ns AS (
    SELECT COALESCE(sqlc.narg('namespace_id')::uuid, (SELECT id FROM ns)) AS id
),
src AS (
    INSERT INTO source (id, namespace_id, kind, name)
    SELECT n.id, t.id, 'oci_registry', @name::text FROM new_id n, target_ns t
    RETURNING id
)
INSERT INTO registry (
    id, type, url, insecure, webhook_secret, repository_patterns, tag_patterns,
    scan_mode, poll_interval_minutes, repositories, auth_username, auth_token,
    include_untagged, verification_mode, trust_public_key, trust_identity,
    trust_issuer, managed_by, managed_ref
)
SELECT
    src.id, @type::text, @url::text, @insecure::boolean, sqlc.narg('webhook_secret')::text,
    @repository_patterns::text[], @tag_patterns::text[], @scan_mode::text,
    @poll_interval_minutes::int, @repositories::text[], sqlc.narg('auth_username')::text,
    sqlc.narg('auth_token')::text, @include_untagged::boolean, @verification_mode::text,
    sqlc.narg('trust_public_key')::text, sqlc.narg('trust_identity')::text, sqlc.narg('trust_issuer')::text,
    sqlc.narg('managed_by')::text, sqlc.narg('managed_ref')::text
FROM src
RETURNING *;

-- name: GetRegistry :one
SELECT sqlc.embed(r), src.name, n.id AS namespace_id, namespace_owner(n.id) AS owner_id, n.visibility
FROM registry r
JOIN source src ON src.id = r.id
JOIN namespace n ON n.id = src.namespace_id
WHERE r.id = $1;

-- name: GetRegistryByName :one
-- Matches on the source name, which is what the caller supplied as the registry
-- name. source.name is unique per namespace, not globally, so once registries
-- share a namespace this can in principle match more than one row; the oldest
-- wins. Callers that need an exact handle should use the id.
SELECT sqlc.embed(r), src.name, n.id AS namespace_id, namespace_owner(n.id) AS owner_id, n.visibility
FROM registry r
JOIN source src ON src.id = r.id
JOIN namespace n ON n.id = src.namespace_id
WHERE src.name = $1
ORDER BY r.created_at ASC
LIMIT 1;

-- name: ListRegistries :many
SELECT sqlc.embed(r), src.name, n.id AS namespace_id, namespace_owner(n.id) AS owner_id, n.visibility
FROM registry r
JOIN source src ON src.id = r.id
JOIN namespace n ON n.id = src.namespace_id
WHERE n.id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
ORDER BY r.created_at ASC;

-- name: ListRegistriesByNamespace :many
-- Registries a namespace owns, in namespace order rather than visibility order.
-- Cluster auto-ingest resolves an image host against these and nothing else: a
-- registry in another namespace could match the host, but using it would let one
-- namespace's cluster trigger pulls with another namespace's credentials.
SELECT sqlc.embed(r), src.name, n.id AS namespace_id, namespace_owner(n.id) AS owner_id, n.visibility
FROM registry r
JOIN source src ON src.id = r.id
JOIN namespace n ON n.id = src.namespace_id
WHERE src.namespace_id = $1
ORDER BY r.created_at ASC;

-- name: ListRegistriesPaged :many
-- owned_only switches from the visibility path to the ownership path, which is
-- what /api/v1/users/me/registries needs — see ListNamespaces.
SELECT sqlc.embed(r), src.name, n.id AS namespace_id, namespace_owner(n.id) AS owner_id, n.visibility, COUNT(*) OVER() AS total_count
FROM registry r
JOIN source src ON src.id = r.id
JOIN namespace n ON n.id = src.namespace_id
WHERE (
    CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
         THEN n.id IN (SELECT owned_namespace_ids(sqlc.narg('user_id')::uuid))
         ELSE n.id IN (SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    END
)
ORDER BY r.created_at ASC
LIMIT @row_limit OFFSET @row_offset;

-- name: UpdateRegistry :one
-- Mirror of CreateRegistry: the channel name lands on source, everything else
-- on registry, in one statement.
--
-- Name and visibility only propagate to the namespace when the registry owns it
-- outright — the id-sharing case CreateRegistry produces for a registry with no
-- explicit namespace. A registry that was created into an existing namespace
-- must not rename it or flip its visibility out from under its siblings; that
-- goes through PATCH /api/v1/namespaces/{id}.
WITH ns AS (
    UPDATE namespace
    SET name       = @name::text,
        visibility = @visibility::text,
        updated_at = now()
    WHERE namespace.id = @id
    RETURNING namespace.id
),
src AS (
    UPDATE source
    SET name       = @name::text,
        updated_at = now()
    WHERE source.id = @id
    RETURNING source.id
)
UPDATE registry
SET type                  = @type::text,
    url                   = @url::text,
    insecure              = @insecure::boolean,
    webhook_secret        = sqlc.narg('webhook_secret')::text,
    enabled               = @enabled::boolean,
    repository_patterns   = @repository_patterns::text[],
    tag_patterns          = @tag_patterns::text[],
    scan_mode             = @scan_mode::text,
    poll_interval_minutes = @poll_interval_minutes::int,
    repositories          = @repositories::text[],
    auth_username         = sqlc.narg('auth_username')::text,
    auth_token            = sqlc.narg('auth_token')::text,
    include_untagged      = @include_untagged::boolean,
    verification_mode     = @verification_mode::text,
    trust_public_key      = sqlc.narg('trust_public_key')::text,
    trust_identity        = sqlc.narg('trust_identity')::text,
    trust_issuer          = sqlc.narg('trust_issuer')::text,
    managed_by            = sqlc.narg('managed_by')::text,
    managed_ref           = sqlc.narg('managed_ref')::text,
    updated_at            = now()
WHERE registry.id = @id
RETURNING *;

-- name: SetRegistryEnabled :one
UPDATE registry
SET enabled    = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateRegistryLastPolled :one
UPDATE registry
SET last_polled_at = now(), updated_at = now()
WHERE id = $1
RETURNING *;

-- name: ListPollableRegistries :many
SELECT sqlc.embed(r), src.name, n.id AS namespace_id, namespace_owner(n.id) AS owner_id, n.visibility
FROM registry r
JOIN source src ON src.id = r.id
JOIN namespace n ON n.id = src.namespace_id
WHERE r.enabled = true AND r.scan_mode IN ('poll', 'both')
ORDER BY r.created_at ASC;

-- name: DeleteRegistry :execrows
-- Deletes the source, which cascades to this registry row. The namespace and
-- its SBOMs survive: previously dropping a registry NULLed sbom.registry_id and
-- a NULL registry was visible to everyone.
DELETE FROM source WHERE id = $1;

-- name: ListRegistryTrustSummary :many
-- Per-registry counts across the five signing statuses, one row per
-- (registry, status) with a nonzero count. Derives each artifact's *current*
-- status from its most recently created SBOM per source — reuses the
-- signing_status() function from ocidex-82g.3 rather than re-deriving. The join
-- to registry restricts this to OCI sources; an upload source has no trust
-- config to summarise. Scoped to the caller's visible namespaces so a namespace
-- owner can read their own signing posture without the admin role.
WITH latest_provenance AS (
    SELECT DISTINCT ON (s.source_id, s.artifact_id)
        s.source_id,
        signing_status(p.data) AS signing_status
    FROM sbom s
    JOIN registry rg ON rg.id = s.source_id
    LEFT JOIN enrichment p ON p.sbom_id = s.id AND p.enricher_name = 'provenance' AND p.status = 'success'
    WHERE s.artifact_id IS NOT NULL
      AND s.namespace_id IN (
          SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    ORDER BY s.source_id, s.artifact_id, s.created_at DESC
)
SELECT source_id AS registry_id, signing_status, COUNT(*) AS artifact_count
FROM latest_provenance
GROUP BY source_id, signing_status
ORDER BY source_id, signing_status;
