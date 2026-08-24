-- +goose Up

-- Holding area for an unconfirmed verified/signed -> unsigned transition.
--
-- "The signature is gone" is the one drift verdict that a silent enricher
-- failure can fabricate: artifact_missing is proven by a 404 HEAD and
-- trust_config_changed by a matching signer, but "unsigned" is the absence of
-- evidence, so anything that stops discovery from finding a signature looks
-- identical to the signature having been removed. A row lands here on the
-- first observation and is only promoted to provenance_drift_events when the
-- next recheck agrees; if the signature reappears instead, the row is dropped
-- and no event is ever written.
--
-- One row per SBOM: a pending observation is superseded by the next one, never
-- accumulated.
CREATE TABLE provenance_drift_pending (
    sbom_id         UUID        PRIMARY KEY REFERENCES sbom(id) ON DELETE CASCADE,
    previous_status TEXT        NOT NULL,
    new_status      TEXT        NOT NULL,
    reason          TEXT        NOT NULL
        CHECK (reason IN ('trust_config_changed', 'artifact_missing', 'reverification_failed')),
    previous_data   JSONB,
    new_data        JSONB,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS provenance_drift_pending;
