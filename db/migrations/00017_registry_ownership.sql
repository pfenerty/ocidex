-- +goose Up
ALTER TABLE registry ADD COLUMN owner_id UUID REFERENCES ocidex_user(id) ON DELETE SET NULL;
ALTER TABLE registry ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public';
ALTER TABLE registry ADD CONSTRAINT registry_visibility_check CHECK (visibility IN ('public', 'private'));

ALTER TABLE sbom ADD COLUMN registry_id UUID REFERENCES registry(id) ON DELETE SET NULL;
CREATE INDEX idx_sbom_registry_id ON sbom(registry_id);

-- +goose Down
DROP INDEX IF EXISTS idx_sbom_registry_id;
ALTER TABLE sbom DROP COLUMN registry_id;

ALTER TABLE registry DROP CONSTRAINT registry_visibility_check;
ALTER TABLE registry DROP COLUMN visibility;
ALTER TABLE registry DROP COLUMN owner_id;
