-- +goose Up
-- W3C trace context of whatever queued the job (ADR-0055 T3): "traceparent",
-- or "traceparent\ntracestate" when a tracestate is set. A worker parents its
-- job span on it however it claimed the row (hint, poll loop or stuck sweep),
-- so one SBOM is one trace across processes. NULL when tracing was off.
ALTER TABLE scan_jobs ADD COLUMN trace_context TEXT;
ALTER TABLE enrichment_jobs ADD COLUMN trace_context TEXT;

-- +goose Down
ALTER TABLE enrichment_jobs DROP COLUMN IF EXISTS trace_context;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS trace_context;
