-- +goose Up

-- Generic enrichment results table. Each enricher (OCI metadata, vulnerability
-- scan, etc.) stores one row per artifact with its structured output in JSONB.
CREATE TABLE enrichment (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id       UUID NOT NULL REFERENCES sbom(id) ON DELETE CASCADE,
    enricher_name TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    data          JSONB,
    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One enrichment result per enricher per SBOM.
CREATE UNIQUE INDEX idx_enrichment_sbom_enricher
    ON enrichment (sbom_id, enricher_name);

-- +goose Down
DROP TABLE IF EXISTS enrichment;
