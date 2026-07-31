-- name: CreateRegistry :one
INSERT INTO registry (name, type, url, insecure, webhook_secret, repository_patterns, tag_patterns, scan_mode, poll_interval_minutes, repositories, auth_username, auth_token, owner_id, visibility, include_untagged, verification_mode, trust_public_key, trust_identity, trust_issuer, managed_by, managed_ref)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
RETURNING *;

-- name: GetRegistry :one
SELECT * FROM registry WHERE id = $1;

-- name: GetRegistryByName :one
SELECT * FROM registry WHERE name = $1;

-- name: ListRegistries :many
SELECT * FROM registry
WHERE (
    sqlc.narg('is_admin')::boolean = true
    OR visibility = 'public'
    OR (sqlc.narg('user_id')::uuid IS NOT NULL AND owner_id = sqlc.narg('user_id')::uuid)
)
ORDER BY created_at ASC;

-- name: ListRegistriesPaged :many
SELECT *, COUNT(*) OVER() AS total_count FROM registry
WHERE (
    sqlc.narg('is_admin')::boolean = true
    OR visibility = 'public'
    OR (sqlc.narg('user_id')::uuid IS NOT NULL AND owner_id = sqlc.narg('user_id')::uuid)
)
ORDER BY created_at ASC
LIMIT @row_limit OFFSET @row_offset;

-- name: UpdateRegistry :one
UPDATE registry
SET name                 = $2,
    type                 = $3,
    url                  = $4,
    insecure             = $5,
    webhook_secret       = $6,
    enabled              = $7,
    repository_patterns  = $8,
    tag_patterns         = $9,
    scan_mode            = $10,
    poll_interval_minutes = $11,
    repositories         = $12,
    auth_username        = $13,
    auth_token           = $14,
    visibility           = $15,
    include_untagged     = $16,
    verification_mode    = $17,
    trust_public_key     = $18,
    trust_identity       = $19,
    trust_issuer         = $20,
    managed_by           = $21,
    managed_ref          = $22,
    updated_at           = now()
WHERE id = $1
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
SELECT * FROM registry
WHERE enabled = true AND scan_mode IN ('poll', 'both')
ORDER BY created_at ASC;

-- name: DeleteRegistry :execrows
DELETE FROM registry WHERE id = $1;

-- name: ListRegistryTrustSummary :many
-- Per-registry counts across the five signing statuses, one row per
-- (registry, status) with a nonzero count. Derives each artifact's *current*
-- status from its most recently created SBOM per registry — reuses the
-- signing_status() function from ocidex-82g.3 rather than re-deriving.
WITH latest_provenance AS (
    SELECT DISTINCT ON (s.registry_id, s.artifact_id)
        s.registry_id,
        signing_status(p.data) AS signing_status
    FROM sbom s
    LEFT JOIN enrichment p ON p.sbom_id = s.id AND p.enricher_name = 'provenance' AND p.status = 'success'
    WHERE s.artifact_id IS NOT NULL
    ORDER BY s.registry_id, s.artifact_id, s.created_at DESC
)
SELECT registry_id, signing_status, COUNT(*) AS artifact_count
FROM latest_provenance
GROUP BY registry_id, signing_status
ORDER BY registry_id, signing_status;
