-- name: InsertScanJob :one
INSERT INTO scan_jobs (registry_id, repository, digest, tag, nats_msg_id)
VALUES (sqlc.narg('registry_id')::uuid, @repository, @digest, sqlc.narg('tag'), sqlc.narg('nats_msg_id'))
RETURNING *;

-- name: StartScanJob :exec
UPDATE scan_jobs
SET state           = 'running',
    started_at      = COALESCE(started_at, now()),
    last_attempt_at = now(),
    worker_id       = @worker_id,
    attempts        = attempts + 1
WHERE nats_msg_id = @nats_msg_id
  AND state NOT IN ('succeeded', 'failed');

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
ORDER BY
    CASE state
        WHEN 'running'   THEN 1
        WHEN 'queued'    THEN 2
        WHEN 'failed'    THEN 3
        WHEN 'succeeded' THEN 4
        ELSE 5
    END,
    created_at DESC
LIMIT sqlc.arg('limit_') OFFSET sqlc.arg('offset_');

-- name: CountScanJobs :one
SELECT COUNT(*) FROM scan_jobs
WHERE (sqlc.narg('state')::text IS NULL OR state = sqlc.narg('state')::text);

-- name: CountScanJobsSince :one
SELECT COUNT(*) FROM scan_jobs
WHERE state = @state::text AND finished_at >= @since::timestamptz;

-- name: GetScanJob :one
SELECT * FROM scan_jobs WHERE id = @id;

-- name: TimeoutScanJobs :exec
UPDATE scan_jobs
SET state = 'failed', finished_at = now(),
    last_error = 'timed out: job was still running after timeout threshold'
WHERE state = 'running'
  AND COALESCE(last_attempt_at, started_at) < @started_before::timestamptz;

-- name: InsertScanJobFailure :one
INSERT INTO scan_job_failures (nats_msg_id, payload, failure_reason, delivery_count)
VALUES (sqlc.narg('nats_msg_id'), @payload, @failure_reason, @delivery_count)
RETURNING *;

-- ClaimStaleQueuedJobs atomically selects scan_jobs stuck in 'queued' past their
-- per-attempt backoff threshold (10m * 2^reconcile_attempts, capped) and increments
-- reconcile_attempts so concurrent worker pods can't double-republish the same row.
-- Returns the data the reconciler needs to rebuild the NATS scan request.
-- name: ClaimStaleQueuedJobs :many
WITH candidates AS (
    SELECT sj.id
    FROM scan_jobs sj
    WHERE sj.state = 'queued'
      AND sj.nats_msg_id IS NOT NULL
      AND sj.reconcile_attempts < @max_attempts::int
      AND sj.created_at < now() - (
          interval '10 minutes' *
          LEAST(power(2, sj.reconcile_attempts)::int, @backoff_cap::int)
      )
    ORDER BY sj.created_at
    LIMIT @batch_size::int
    FOR UPDATE SKIP LOCKED
)
UPDATE scan_jobs sj
SET reconcile_attempts = sj.reconcile_attempts + 1
FROM candidates c, registry r
WHERE sj.id = c.id
  AND r.id = sj.registry_id
RETURNING
    sj.nats_msg_id::text          AS nats_msg_id,
    r.id::text                    AS registry_id,
    sj.repository                 AS repository,
    sj.digest                     AS digest,
    COALESCE(sj.tag, '')::text    AS tag,
    r.url                         AS registry_url,
    r.insecure                    AS insecure,
    COALESCE(r.auth_username, '')::text AS auth_username,
    COALESCE(r.auth_token, '')::text    AS auth_token,
    sj.reconcile_attempts         AS reconcile_attempts;

-- FailExhaustedQueuedJobs marks queued jobs that exceeded the reconciler attempt
-- budget as permanently failed so they stop being scanned every tick.
-- name: FailExhaustedQueuedJobs :exec
UPDATE scan_jobs
SET state       = 'failed',
    finished_at = now(),
    last_error  = 'orphaned: max reconcile attempts'
WHERE state = 'queued'
  AND reconcile_attempts >= @max_attempts::int;

-- name: ListScanJobFailures :many
SELECT id, nats_msg_id, failure_reason, delivery_count, created_at
FROM scan_job_failures
ORDER BY created_at DESC
LIMIT sqlc.arg('limit_') OFFSET sqlc.arg('offset_');

-- name: CountScanJobFailures :one
SELECT COUNT(*) FROM scan_job_failures;

-- name: DeleteOldScanJobFailures :execrows
DELETE FROM scan_job_failures
WHERE created_at < @cutoff::timestamptz;
