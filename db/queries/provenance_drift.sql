-- name: InsertProvenanceDrift :exec
INSERT INTO provenance_drift_events (sbom_id, previous_status, new_status, reason, previous_data, new_data)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetLatestProvenanceDrift :one
SELECT id, sbom_id, previous_status, new_status, reason, previous_data, new_data, detected_at
FROM provenance_drift_events
WHERE sbom_id = $1
ORDER BY detected_at DESC
LIMIT 1;
