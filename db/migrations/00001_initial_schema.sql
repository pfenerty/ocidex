-- +goose Up

-- sbom: top-level BOM document
CREATE TABLE sbom (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number TEXT,
    spec_version  TEXT NOT NULL,
    version       INT NOT NULL DEFAULT 1,
    raw_bom       JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_sbom_serial_version
    ON sbom (serial_number, version)
    WHERE serial_number IS NOT NULL;

-- license: deduplicated license registry
CREATE TABLE license (
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spdx_id TEXT,
    name    TEXT NOT NULL,
    url     TEXT
);

CREATE UNIQUE INDEX idx_license_spdx_id
    ON license (spdx_id)
    WHERE spdx_id IS NOT NULL;

CREATE UNIQUE INDEX idx_license_name_no_spdx
    ON license (name)
    WHERE spdx_id IS NULL;

-- component: normalized from BOM components
CREATE TABLE component (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id       UUID NOT NULL REFERENCES sbom(id) ON DELETE CASCADE,
    parent_id     UUID REFERENCES component(id) ON DELETE CASCADE,
    bom_ref       TEXT,
    type          TEXT NOT NULL,
    name          TEXT NOT NULL,
    group_name    TEXT,
    version       TEXT,
    version_major INT,
    version_minor INT,
    version_patch INT,
    purl          TEXT,
    cpe           TEXT,
    description   TEXT,
    scope         TEXT,
    publisher     TEXT,
    copyright     TEXT
);

CREATE INDEX idx_component_sbom_id ON component (sbom_id);
CREATE INDEX idx_component_name_group ON component (name, group_name);
CREATE INDEX idx_component_purl ON component (purl) WHERE purl IS NOT NULL;
CREATE INDEX idx_component_version_parts ON component (name, version_major, version_minor, version_patch);

-- component_hash
CREATE TABLE component_hash (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id UUID NOT NULL REFERENCES component(id) ON DELETE CASCADE,
    algorithm    TEXT NOT NULL,
    value        TEXT NOT NULL
);

CREATE INDEX idx_component_hash_component_id ON component_hash (component_id);

-- component_license: join table
CREATE TABLE component_license (
    component_id UUID NOT NULL REFERENCES component(id) ON DELETE CASCADE,
    license_id   UUID NOT NULL REFERENCES license(id) ON DELETE CASCADE,
    PRIMARY KEY (component_id, license_id)
);

-- dependency: directed edges between components within a BOM
CREATE TABLE dependency (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id    UUID NOT NULL REFERENCES sbom(id) ON DELETE CASCADE,
    ref        TEXT NOT NULL,
    depends_on TEXT NOT NULL
);

CREATE INDEX idx_dependency_sbom_ref ON dependency (sbom_id, ref);

-- external_reference
CREATE TABLE external_reference (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id UUID NOT NULL REFERENCES component(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,
    url          TEXT NOT NULL,
    comment      TEXT
);

CREATE INDEX idx_external_reference_component_id ON external_reference (component_id);

-- +goose Down
DROP TABLE IF EXISTS external_reference;
DROP TABLE IF EXISTS dependency;
DROP TABLE IF EXISTS component_license;
DROP TABLE IF EXISTS component_hash;
DROP TABLE IF EXISTS component;
DROP TABLE IF EXISTS license;
DROP TABLE IF EXISTS sbom;
