-- name: UpsertEnrichment :exec
-- A transient enricher error must not clobber a prior successful result: status
-- only moves to 'error' if there was no prior good data, and data is preserved
-- via COALESCE when the new result carries none (see ocidex-goh.2).
INSERT INTO enrichment (sbom_id, enricher_name, status, data, error_message, updated_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (sbom_id, enricher_name)
DO UPDATE SET
    status = CASE
        WHEN EXCLUDED.status = 'error' AND enrichment.data IS NOT NULL THEN enrichment.status
        ELSE EXCLUDED.status
    END,
    data = COALESCE(EXCLUDED.data, enrichment.data),
    error_message = EXCLUDED.error_message,
    updated_at = now();

-- name: GetEnrichment :one
SELECT id, sbom_id, enricher_name, status, data, error_message, created_at, updated_at
FROM enrichment
WHERE sbom_id = $1 AND enricher_name = $2;

-- name: ListEnrichmentsBySBOM :many
SELECT id, enricher_name, status, data, error_message, updated_at
FROM enrichment
WHERE sbom_id = $1
ORDER BY enricher_name;

-- name: ListSBOMEnrichmentsByArtifact :many
SELECT e.sbom_id, e.enricher_name, e.data
FROM enrichment e
JOIN sbom s ON s.id = e.sbom_id
WHERE s.artifact_id = $1 AND e.status = 'success'
ORDER BY e.sbom_id;

-- name: UpdateSBOMEnrichmentSufficient :exec
UPDATE sbom SET enrichment_sufficient = $2 WHERE id = $1;

-- name: ListSBOMsDueForProvenanceRecheck :many
SELECT sbom_id
FROM enrichment
WHERE enricher_name = 'provenance'
  AND status = 'success'
  AND updated_at < @cutoff::timestamptz
ORDER BY updated_at
LIMIT @row_limit::int;
