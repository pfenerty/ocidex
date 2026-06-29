-- name: InsertEnrichmentJob :one
INSERT INTO enrichment_jobs (sbom_id, idempotency_key, architecture, build_date, enricher_name)
VALUES (
    @sbom_id::uuid,
    sqlc.narg('idempotency_key'),
    sqlc.narg('architecture'),
    sqlc.narg('build_date'),
    @enricher_name::text
)
RETURNING *;

-- name: ClaimEnrichmentJobByID :one
WITH claimed AS (
    UPDATE enrichment_jobs
    SET state           = 'running',
        started_at      = COALESCE(started_at, now()),
        last_attempt_at = now(),
        worker_id       = @worker_id::text,
        attempts        = attempts + 1
    WHERE id = @id::uuid
      AND state = 'queued'
    RETURNING id, sbom_id, attempts, architecture, build_date
)
SELECT
    c.id,
    c.sbom_id,
    c.attempts,
    COALESCE(c.architecture, '')::text        AS architecture,
    COALESCE(c.build_date, '')::text          AS build_date,
    COALESCE(s.digest, '')::text              AS digest,
    COALESCE(s.index_digest, '')::text        AS index_digest,
    COALESCE(s.subject_version, '')::text     AS subject_version,
    COALESCE(a.type, '')::text                AS artifact_type,
    COALESCE(a.name, '')::text                AS artifact_name
FROM claimed c
JOIN sbom s ON s.id = c.sbom_id
JOIN artifact a ON a.id = s.artifact_id;

-- name: ClaimNextEnrichmentJob :one
WITH next_id AS (
    SELECT id FROM enrichment_jobs
    WHERE state = 'queued'
      AND enricher_name = @enricher_name::text
    ORDER BY created_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED
),
claimed AS (
    UPDATE enrichment_jobs
    SET state           = 'running',
        started_at      = COALESCE(started_at, now()),
        last_attempt_at = now(),
        worker_id       = @worker_id::text,
        attempts        = attempts + 1
    WHERE id IN (SELECT id FROM next_id)
    RETURNING id, sbom_id, attempts, architecture, build_date, enricher_name
)
SELECT
    c.id,
    c.sbom_id,
    c.attempts,
    COALESCE(c.architecture, '')::text        AS architecture,
    COALESCE(c.build_date, '')::text          AS build_date,
    c.enricher_name                           AS enricher_name,
    COALESCE(s.digest, '')::text              AS digest,
    COALESCE(s.index_digest, '')::text        AS index_digest,
    COALESCE(s.subject_version, '')::text     AS subject_version,
    COALESCE(a.type, '')::text                AS artifact_type,
    COALESCE(a.name, '')::text                AS artifact_name
FROM claimed c
JOIN sbom s ON s.id = c.sbom_id
JOIN artifact a ON a.id = s.artifact_id;

-- name: FinishEnrichmentJobByID :exec
UPDATE enrichment_jobs
SET state = 'succeeded', finished_at = now()
WHERE id = @id::uuid;

-- FailOrRequeueEnrichmentJobByID transitions a running job back to 'queued'
-- for retry, or to 'failed' when the retry budget is exhausted.
-- name: FailOrRequeueEnrichmentJobByID :one
UPDATE enrichment_jobs
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

-- RequeueStuckEnrichmentJobs sweeps running rows whose worker has gone silent.
-- name: RequeueStuckEnrichmentJobs :exec
UPDATE enrichment_jobs
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

-- ListEnrichmentJobs returns enrichment jobs for the admin Jobs page, optionally
-- filtered by state and/or enricher, joined to the SBOM/artifact for display.
-- name: ListEnrichmentJobs :many
SELECT
    j.id, j.sbom_id, j.state, j.attempts, j.last_error, j.worker_id,
    j.enricher_name, j.created_at, j.started_at, j.last_attempt_at, j.finished_at,
    s.digest AS sbom_digest,
    a.name   AS artifact_name
FROM enrichment_jobs j
LEFT JOIN sbom s     ON s.id = j.sbom_id
LEFT JOIN artifact a ON a.id = s.artifact_id
WHERE (sqlc.narg('state')::text IS NULL OR j.state = sqlc.narg('state')::text)
  AND (sqlc.narg('enricher_name')::text IS NULL OR j.enricher_name = sqlc.narg('enricher_name')::text)
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

-- name: CountEnrichmentJobs :one
SELECT COUNT(*) FROM enrichment_jobs j
WHERE (sqlc.narg('state')::text IS NULL OR j.state = sqlc.narg('state')::text)
  AND (sqlc.narg('enricher_name')::text IS NULL OR j.enricher_name = sqlc.narg('enricher_name')::text);

-- SummarizeEnrichmentJobs returns one row per (enricher, state) with its count,
-- powering the per-enricher health matrix on the admin Jobs page.
-- name: SummarizeEnrichmentJobs :many
SELECT enricher_name, state, COUNT(*) AS count
FROM enrichment_jobs
GROUP BY enricher_name, state;

-- name: RetryEnrichmentJob :exec
UPDATE enrichment_jobs
SET state           = 'queued',
    attempts        = 0,
    last_error      = NULL,
    finished_at     = NULL,
    started_at      = NULL,
    last_attempt_at = NULL
WHERE id = @id::uuid
  AND state = 'failed';

-- RetryAllFailedEnrichmentJobs resets every 'failed' row back to 'queued',
-- optionally scoped to a single enricher. Returns the row count.
-- name: RetryAllFailedEnrichmentJobs :execrows
UPDATE enrichment_jobs
SET state           = 'queued',
    attempts        = 0,
    last_error      = NULL,
    finished_at     = NULL,
    started_at      = NULL,
    last_attempt_at = NULL
WHERE state = 'failed'
  AND (sqlc.narg('enricher_name')::text IS NULL OR enricher_name = sqlc.narg('enricher_name')::text);
