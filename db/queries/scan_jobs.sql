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

-- Outbox-pattern queries. The scan_jobs row IS the queue; NATS hints just
-- trigger faster wakeup. ClaimScanJobByID handles the hint path; ClaimNextQueuedJob
-- handles the poll-loop fallback. Both atomically transition queued → running and
-- return the data needed to run the scan.
--
-- Historical: this file previously contained ClaimStaleQueuedJobs and
-- FailExhaustedQueuedJobs (the NATS-aware reconciler). Removed in
-- ocidex-ujj.74 alongside the dual-write design they papered over.

-- name: ClaimScanJobByID :one
WITH claimed AS (
    UPDATE scan_jobs
    SET state           = 'running',
        started_at      = COALESCE(started_at, now()),
        last_attempt_at = now(),
        worker_id       = @worker_id::text,
        attempts        = attempts + 1
    WHERE id = @id::uuid
      AND state = 'queued'
    RETURNING id, registry_id, repository, digest, tag, attempts
)
SELECT
    c.id,
    COALESCE(c.registry_id::text, '')::text     AS registry_id,
    c.repository,
    c.digest,
    COALESCE(c.tag, '')::text                   AS tag,
    COALESCE(r.url, '')::text                   AS registry_url,
    COALESCE(r.insecure, false)::bool           AS insecure,
    COALESCE(r.auth_username, '')::text         AS auth_username,
    COALESCE(r.auth_token, '')::text            AS auth_token,
    c.attempts
FROM claimed c
LEFT JOIN registry r ON r.id = c.registry_id;

-- name: ClaimNextQueuedJob :one
WITH next_id AS (
    SELECT id FROM scan_jobs
    WHERE state = 'queued'
    ORDER BY created_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED
),
claimed AS (
    UPDATE scan_jobs
    SET state           = 'running',
        started_at      = COALESCE(started_at, now()),
        last_attempt_at = now(),
        worker_id       = @worker_id::text,
        attempts        = attempts + 1
    WHERE id IN (SELECT id FROM next_id)
    RETURNING id, registry_id, repository, digest, tag, attempts
)
SELECT
    c.id,
    COALESCE(c.registry_id::text, '')::text     AS registry_id,
    c.repository,
    c.digest,
    COALESCE(c.tag, '')::text                   AS tag,
    COALESCE(r.url, '')::text                   AS registry_url,
    COALESCE(r.insecure, false)::bool           AS insecure,
    COALESCE(r.auth_username, '')::text         AS auth_username,
    COALESCE(r.auth_token, '')::text            AS auth_token,
    c.attempts
FROM claimed c
LEFT JOIN registry r ON r.id = c.registry_id;

-- name: FinishScanJobByID :exec
UPDATE scan_jobs
SET state = 'succeeded', finished_at = now(), sbom_id = sqlc.narg('sbom_id')::uuid
WHERE id = @id::uuid;

-- FailOrRequeueScanJobByID transitions a 'running' job back to 'queued' for
-- retry, or to 'failed' if it has exhausted its attempts. Idempotent on
-- already-terminal rows: the WHERE clause skips them.
-- name: FailOrRequeueScanJobByID :one
UPDATE scan_jobs
SET state       = CASE
        WHEN attempts >= @max_attempts::int THEN 'failed'
        ELSE 'queued'
    END,
    last_error  = @last_error,
    finished_at = CASE
        WHEN attempts >= @max_attempts::int THEN now()
        ELSE NULL
    END
WHERE id = @id::uuid
  AND state NOT IN ('succeeded', 'failed')
RETURNING state;

-- RetryScanJob resets a failed row back to 'queued' with cleared retry state,
-- so an operator can manually retry a permanently-failed scan. The row is
-- picked up by the poll loop or a fresh NATS hint.
-- name: RetryScanJob :exec
UPDATE scan_jobs
SET state       = 'queued',
    attempts    = 0,
    last_error  = NULL,
    finished_at = NULL,
    started_at  = NULL,
    last_attempt_at = NULL
WHERE id = @id::uuid
  AND state = 'failed';

-- RequeueStuckRunning replaces the orphan reconciler. A 'running' row whose
-- worker hasn't updated last_attempt_at recently is presumed dead; we move it
-- back to 'queued' for another worker to claim, or 'failed' if it has used up
-- its retries. This is the only stuck-job sweep the outbox model needs.
-- name: RequeueStuckRunning :exec
UPDATE scan_jobs
SET state = CASE
        WHEN attempts >= @max_attempts::int THEN 'failed'
        ELSE 'queued'
    END,
    last_error = CASE
        WHEN attempts >= @max_attempts::int
            THEN 'stuck: worker did not complete and retries exhausted'
        ELSE last_error
    END,
    finished_at = CASE
        WHEN attempts >= @max_attempts::int THEN now()
        ELSE NULL
    END
WHERE state = 'running'
  AND last_attempt_at < @stuck_before::timestamptz;
