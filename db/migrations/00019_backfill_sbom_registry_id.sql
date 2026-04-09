-- +goose Up
-- Backfill sbom.registry_id by matching artifact names to registry URLs.
-- Artifact names are prefixed with the registry URL (e.g. "ghcr.io/org/repo" or "zot:5000/lib/alpine").
UPDATE sbom s
SET registry_id = r.id
FROM artifact a, registry r
WHERE s.artifact_id = a.id
  AND s.registry_id IS NULL
  AND a.name LIKE r.url || '/%';

-- +goose Down
-- No rollback: we can't know which rows were originally NULL vs. intentionally set.
