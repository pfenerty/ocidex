-- +goose Up
-- The reconcile_attempts column belonged to the NATS-aware orphan reconciler
-- (00030). Under the outbox pattern the scan_jobs row is the source of truth
-- and no reconciliation across DB + NATS exists, so the column is gone.
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS reconcile_attempts;

-- +goose Down
ALTER TABLE scan_jobs ADD COLUMN reconcile_attempts INT NOT NULL DEFAULT 0;
