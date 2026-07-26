-- +goose Up

-- Append-only log of provenance signing-status changes. The `enrichment`
-- table is upsert-only (one row per sbom_id+enricher_name), so history of
-- how a SBOM's verification status changed over time must live separately.
CREATE TABLE provenance_drift_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id         UUID        NOT NULL REFERENCES sbom(id) ON DELETE CASCADE,
    previous_status TEXT        NOT NULL,
    new_status      TEXT        NOT NULL,
    reason          TEXT        NOT NULL
        CHECK (reason IN ('trust_config_changed', 'artifact_missing', 'reverification_failed')),
    previous_data   JSONB,
    new_data        JSONB,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_provenance_drift_sbom ON provenance_drift_events (sbom_id, detected_at DESC);

-- +goose Down
DROP TABLE IF EXISTS provenance_drift_events;
