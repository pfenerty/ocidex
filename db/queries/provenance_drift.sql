-- name: InsertProvenanceDrift :exec
INSERT INTO provenance_drift_events (sbom_id, previous_status, new_status, reason, previous_data, new_data)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetLatestProvenanceDrift :one
SELECT id, sbom_id, previous_status, new_status, reason, previous_data, new_data, detected_at
FROM provenance_drift_events
WHERE sbom_id = $1
ORDER BY detected_at DESC
LIMIT 1;

-- name: ListProvenanceDriftBySBOM :many
SELECT id, sbom_id, previous_status, new_status, reason, detected_at,
       COUNT(*) OVER() AS total_count
FROM provenance_drift_events
WHERE sbom_id = $1
ORDER BY detected_at DESC
LIMIT @row_limit OFFSET @row_offset;

-- name: ListRecentProvenanceDrift :many
SELECT
    d.id, d.sbom_id, d.previous_status, d.new_status, d.reason, d.detected_at,
    s.source_id, s.artifact_id,
    a.name AS artifact_name, a.type AS artifact_type,
    src.name AS source_name,
    COUNT(*) OVER() AS total_count
FROM provenance_drift_events d
JOIN sbom s ON s.id = d.sbom_id
LEFT JOIN artifact a ON a.id = s.artifact_id
LEFT JOIN source src ON src.id = s.source_id
ORDER BY d.detected_at DESC
LIMIT @row_limit OFFSET @row_offset;
