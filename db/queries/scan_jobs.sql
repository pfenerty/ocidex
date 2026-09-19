-- name: InsertScanJob :one
-- On conflict with a 'succeeded' row, reset it to queued so a re-scan of an
-- already-scanned digest works. On conflict with an active row
-- (queued/running), leave it unchanged — the existing job is still running.
--
-- 'failed' is deliberately NOT reset here. This query is what every catalog
-- walk calls for every image it sees, so resetting a failed row meant a
-- deterministically-broken image (one syft cannot read, one whose ingest
-- always errors, one too big for the worker) got its attempts zeroed on every
-- poll and re-ran forever: state churned queued → running → failed → queued on
-- the registry's poll interval, and the failure was never visible for longer
-- than one cycle. On ocidex.app that hid a 13-day crash loop behind a row that
-- always looked freshly started. A failed row now stays failed and is
-- requeued only by an explicit operator action — RetryScanJob (the Retry
-- button) or RetryAllFailedScanJobs.
--
-- A transient failure therefore needs that one click. It already had a retry
-- budget of SCANNER_MAX_ATTEMPTS to ride out a blip, so what this gives up is
-- automatic recovery from an outage longer than the budget — in exchange for a
-- failed row that is still there to be read.
INSERT INTO scan_jobs (registry_id, repository, digest, index_digest, tag, nats_msg_id)
VALUES (sqlc.narg('registry_id')::uuid, @repository, @digest, sqlc.narg('index_digest'), sqlc.narg('tag'), sqlc.narg('nats_msg_id'))
ON CONFLICT (nats_msg_id) DO UPDATE
    SET state           = CASE WHEN scan_jobs.state = 'succeeded' THEN 'queued'::text ELSE scan_jobs.state           END,
        attempts        = CASE WHEN scan_jobs.state = 'succeeded' THEN 0              ELSE scan_jobs.attempts        END,
        last_error      = CASE WHEN scan_jobs.state = 'succeeded' THEN NULL           ELSE scan_jobs.last_error      END,
        finished_at     = CASE WHEN scan_jobs.state = 'succeeded' THEN NULL           ELSE scan_jobs.finished_at     END,
        started_at      = CASE WHEN scan_jobs.state = 'succeeded' THEN NULL           ELSE scan_jobs.started_at      END,
        last_attempt_at = CASE WHEN scan_jobs.state = 'succeeded' THEN NULL           ELSE scan_jobs.last_attempt_at END,
        sbom_id         = CASE WHEN scan_jobs.state = 'succeeded' THEN NULL           ELSE scan_jobs.sbom_id         END,
        index_digest    = EXCLUDED.index_digest,
        tag             = EXCLUDED.tag
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

-- Scan jobs hang off a registry, and a registry inherits its visibility from the
-- namespace above it (ADR-039). scan_jobs.registry_id is nullable — a row whose
-- registry has been deleted belongs to no namespace, so it is admin-only. The
-- state bucket in ORDER BY is mutable, which is why these stay OFFSET-paginated
-- rather than keyset (ADR-043 rule 1).

-- name: ListScanJobs :many
SELECT j.* FROM scan_jobs j
WHERE (sqlc.narg('state')::text IS NULL OR j.state = sqlc.narg('state')::text)
  AND (
    COALESCE(sqlc.narg('is_admin')::boolean, false)
    OR EXISTS (
        SELECT 1 FROM source src
        WHERE src.id = j.registry_id
          AND src.namespace_id IN (
              SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    )
  )
ORDER BY
    CASE j.state
        WHEN 'running'   THEN 1
        WHEN 'queued'    THEN 2
        WHEN 'failed'    THEN 3
        WHEN 'succeeded' THEN 4
        ELSE 5
    END,
    j.created_at DESC
LIMIT sqlc.arg('limit_') OFFSET sqlc.arg('offset_');

-- name: CountScanJobs :one
SELECT COUNT(*) FROM scan_jobs j
WHERE (sqlc.narg('state')::text IS NULL OR j.state = sqlc.narg('state')::text)
  AND (
    COALESCE(sqlc.narg('is_admin')::boolean, false)
    OR EXISTS (
        SELECT 1 FROM source src
        WHERE src.id = j.registry_id
          AND src.namespace_id IN (
              SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    )
  );

-- name: CountScanJobsSince :one
SELECT COUNT(*) FROM scan_jobs
WHERE state = @state::text AND finished_at >= @since::timestamptz;

-- name: GetScanJob :one
-- Visibility-filtered on the same rule as ListScanJobs, so a job in a namespace
-- the caller cannot see 404s rather than leaking its repository and digest.
SELECT j.* FROM scan_jobs j
WHERE j.id = @id
  AND (
    COALESCE(sqlc.narg('is_admin')::boolean, false)
    OR EXISTS (
        SELECT 1 FROM source src
        WHERE src.id = j.registry_id
          AND src.namespace_id IN (
              SELECT visible_namespace_ids(sqlc.narg('user_id')::uuid, sqlc.narg('is_admin')::boolean))
    )
  );

-- name: TimeoutScanJobs :exec
UPDATE scan_jobs
SET state = 'failed', finished_at = now(),
    last_error = 'timed out: job was still running after timeout threshold'
WHERE state = 'running'
  AND COALESCE(last_attempt_at, started_at) < @started_before::timestamptz;

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
    RETURNING id, registry_id, repository, digest, index_digest, tag, attempts
)
SELECT
    c.id,
    COALESCE(c.registry_id::text, '')::text     AS registry_id,
    c.repository,
    c.digest,
    COALESCE(c.index_digest, '')::text          AS index_digest,
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
    RETURNING id, registry_id, repository, digest, index_digest, tag, attempts
)
SELECT
    c.id,
    COALESCE(c.registry_id::text, '')::text     AS registry_id,
    c.repository,
    c.digest,
    COALESCE(c.index_digest, '')::text          AS index_digest,
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

-- RetryAllFailedScanJobs resets every 'failed' row back to 'queued' with cleared
-- retry state. Returns the row count so the caller can surface it to the operator.
-- name: RetryAllFailedScanJobs :execrows
UPDATE scan_jobs
SET state       = 'queued',
    attempts    = 0,
    last_error  = NULL,
    finished_at = NULL,
    started_at  = NULL,
    last_attempt_at = NULL
WHERE state = 'failed';

-- RequeueStuckRunning replaces the orphan reconciler. A 'running' row whose
-- worker hasn't updated last_attempt_at recently is presumed dead; we move it
-- back to 'queued' for another worker to claim, or 'failed' if it has used up
-- its retries. This is the only stuck-job sweep the outbox model needs.
--
-- Both branches record why. A worker that dies without returning -- OOMKilled
-- on a large image, evicted, SIGKILLed -- never reaches FailOrRequeue, so
-- before this the requeue branch left last_error untouched and the row read as
-- attempts=N with no error at all. That is the one failure mode the operator
-- cannot diagnose from the row, and it is the common one for an image too big
-- for the worker's memory limit.
-- name: RequeueStuckRunning :exec
UPDATE scan_jobs
SET state = CASE
        WHEN attempts >= @max_attempts::int THEN 'failed'
        ELSE 'queued'
    END,
    last_error = CASE
        WHEN attempts >= @max_attempts::int
            THEN 'stuck: worker did not complete and retries exhausted'
        ELSE 'stuck: worker did not complete (no error reported); requeued for retry'
    END,
    finished_at = CASE
        WHEN attempts >= @max_attempts::int THEN now()
        ELSE NULL
    END
WHERE state = 'running'
  AND last_attempt_at < @stuck_before::timestamptz;
