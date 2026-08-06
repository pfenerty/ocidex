-- +goose Up

-- enrichment_sufficient was defined when every artifact was an image: it is set
-- only when enrichment JSON carries both imageVersion and architecture. A binary
-- or library uploaded under ADR-040 has no OCI image to read an architecture
-- from, so the flag stayed false forever and GET /api/v1/artifacts -- which
-- defaults to require_sufficient=true -- hid every non-container artifact.
--
-- The dispatcher now requires architecture only for the types that can have one.
-- That rule only fires when an enricher next runs, so correct the rows already
-- in the table: a non-container SBOM whose version is known is as enriched as it
-- is ever going to get.
--
-- Deliberately keyed on subject_version rather than the enrichment payload. It
-- is the column the sufficiency signal ultimately feeds, it is already populated
-- by ingest for caller-declared subjects, and it does not depend on which
-- enricher happened to write the row.
UPDATE sbom s
SET enrichment_sufficient = true
FROM artifact a
WHERE a.id = s.artifact_id
  AND a.type <> 'container'
  AND s.subject_version IS NOT NULL
  AND s.subject_version <> ''
  AND NOT s.enrichment_sufficient;

-- +goose Down

-- Restores the container-only rule for the same rows. This is lossy in the same
-- way the Up is: neither can distinguish a row this migration flipped from one
-- an enricher set afterwards, so the Down re-hides every non-container SBOM
-- without an architecture, which is exactly the pre-migration state.
UPDATE sbom s
SET enrichment_sufficient = false
FROM artifact a
WHERE a.id = s.artifact_id
  AND a.type <> 'container'
  AND s.enrichment_sufficient
  AND NOT EXISTS (
        SELECT 1 FROM enrichment e
        WHERE e.sbom_id = s.id
          AND e.status = 'success'
          AND e.data ->> 'architecture' IS NOT NULL
          AND e.data ->> 'architecture' <> ''
      );
