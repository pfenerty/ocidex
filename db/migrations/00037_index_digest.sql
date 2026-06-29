-- +goose Up
-- index_digest records the multi-arch image index a per-platform child was
-- scanned from. cosign/Tekton Chains sign the index (the tag target), not the
-- per-platform child, so the provenance enricher must look up sig/att on the
-- index digest. NULL for single-arch images scanned directly.
ALTER TABLE scan_jobs ADD COLUMN index_digest TEXT;
ALTER TABLE sbom ADD COLUMN index_digest TEXT;

-- +goose Down
ALTER TABLE sbom DROP COLUMN IF EXISTS index_digest;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS index_digest;
