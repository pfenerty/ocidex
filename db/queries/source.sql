-- Source is the ingest channel (ADR-039). `kind` is the subtype discriminator
-- ('oci_registry' | 'upload'); an oci_registry source has a matching registry
-- row sharing its id, an upload source has none.

-- name: CreateSource :one
INSERT INTO source (namespace_id, kind, name)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSource :one
SELECT * FROM source WHERE id = $1;

-- name: GetSourceByName :one
SELECT * FROM source WHERE namespace_id = $1 AND name = $2;

-- name: ListSourcesByNamespace :many
SELECT * FROM source WHERE namespace_id = $1 ORDER BY created_at ASC;

-- name: ListSources :many
-- Visibility is resolved through the owning namespace, so a source is never
-- listed to a viewer who cannot see the namespace holding it. owned_only
-- switches to the ownership path — see ListNamespaces for why the two live in
-- one query.
SELECT sqlc.embed(s), n.name AS namespace_name, n.owner_id, n.visibility
FROM source s
JOIN namespace n ON n.id = s.namespace_id
WHERE (
    CASE WHEN COALESCE(sqlc.narg('owned_only')::boolean, false)
         THEN n.owner_id = sqlc.narg('user_id')::uuid
         ELSE sqlc.narg('is_admin')::boolean = true
              OR n.visibility = 'public'
              OR (sqlc.narg('user_id')::uuid IS NOT NULL AND n.owner_id = sqlc.narg('user_id')::uuid)
    END
)
ORDER BY s.created_at ASC;

-- name: UpdateSource :one
UPDATE source
SET name       = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteSource :execrows
-- Cascades to the registry subtype row. The owning namespace is deliberately
-- left standing: a namespace outliving its last source is correct, not a leak
-- (ADR-039). SBOMs keep their namespace and only lose source_id.
DELETE FROM source WHERE id = $1;
