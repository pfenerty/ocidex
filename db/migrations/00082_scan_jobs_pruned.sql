-- +goose Up
-- ADR-0053 S6: 'pruned' is the tombstone an explicit delete of a
-- registry-sourced SBOM leaves on its scan job, so the next catalog walk does
-- not scan the digest again. InsertScanJob leaves a pruned row alone unless the
-- walk is forced; the claim queries only ever take 'queued' rows.
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_state_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_state_check
    CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'pruned'));

-- +goose Down
-- A pruned job has no SBOM; 'succeeded' is the state it was in before the delete.
UPDATE scan_jobs SET state = 'succeeded' WHERE state = 'pruned';
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_state_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_state_check
    CHECK (state IN ('queued', 'running', 'succeeded', 'failed'));
