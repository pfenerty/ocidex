-- name: InsertScanJob :one
INSERT INTO scan_jobs (registry_id, repository, digest, tag, nats_msg_id)
VALUES (sqlc.narg('registry_id')::uuid, @repository, @digest, sqlc.narg('tag'), sqlc.narg('nats_msg_id'))
RETURNING *;

-- name: StartScanJob :exec
UPDATE scan_jobs
SET state = 'running', started_at = now(), attempts = attempts + 1
WHERE nats_msg_id = @nats_msg_id;

-- name: FinishScanJob :exec
UPDATE scan_jobs
SET state = 'succeeded', finished_at = now(), sbom_id = sqlc.narg('sbom_id')::uuid
WHERE nats_msg_id = @nats_msg_id;

-- name: FailScanJob :exec
UPDATE scan_jobs
SET state = 'failed', finished_at = now(), last_error = sqlc.narg('last_error')
WHERE nats_msg_id = @nats_msg_id;

-- name: ListScanJobs :many
SELECT * FROM scan_jobs
WHERE (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state')::text)
ORDER BY created_at DESC
LIMIT sqlc.arg('limit_') OFFSET sqlc.arg('offset_');

-- name: CountScanJobs :one
SELECT COUNT(*) FROM scan_jobs
WHERE (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state')::text);

-- name: CountScanJobsSince :one
SELECT COUNT(*) FROM scan_jobs
WHERE state = @state::text AND finished_at >= @since::timestamptz;

-- name: GetScanJob :one
SELECT * FROM scan_jobs WHERE id = @id;
