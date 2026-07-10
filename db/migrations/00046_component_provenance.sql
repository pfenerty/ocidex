-- +goose Up
ALTER TABLE component ADD COLUMN layer_id       TEXT;
ALTER TABLE component ADD COLUMN found_by       TEXT;
ALTER TABLE component ADD COLUMN source_package TEXT;
ALTER TABLE component ADD COLUMN source_version TEXT;
ALTER TABLE component ADD COLUMN source_purl    TEXT;

CREATE INDEX idx_component_found_by       ON component (found_by)       WHERE found_by IS NOT NULL;
CREATE INDEX idx_component_source_package ON component (source_package) WHERE source_package IS NOT NULL;
CREATE INDEX idx_component_layer_id       ON component (layer_id)       WHERE layer_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_component_layer_id;
DROP INDEX IF EXISTS idx_component_source_package;
DROP INDEX IF EXISTS idx_component_found_by;
ALTER TABLE component DROP COLUMN IF EXISTS source_purl;
ALTER TABLE component DROP COLUMN IF EXISTS source_version;
ALTER TABLE component DROP COLUMN IF EXISTS source_package;
ALTER TABLE component DROP COLUMN IF EXISTS found_by;
ALTER TABLE component DROP COLUMN IF EXISTS layer_id;
