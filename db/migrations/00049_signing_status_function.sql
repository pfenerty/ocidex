-- +goose Up
CREATE FUNCTION signing_status(provenance_data jsonb) RETURNS text
LANGUAGE SQL IMMUTABLE AS $$
    SELECT CASE
        WHEN (provenance_data->>'artifactMissing')::boolean = true THEN 'artifact_missing'
        WHEN (provenance_data->>'verified')::boolean = true THEN 'verified'
        WHEN (provenance_data->>'verified')::boolean = false THEN 'verification_failed'
        WHEN (provenance_data->>'signaturePresent')::boolean = true
             OR (provenance_data->>'attestationPresent')::boolean = true THEN 'signed'
        ELSE 'unsigned'
    END
$$;

-- +goose Down
DROP FUNCTION IF EXISTS signing_status(jsonb);
