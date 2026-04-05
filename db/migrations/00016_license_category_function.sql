-- +goose Up
CREATE OR REPLACE FUNCTION license_category(spdx_id TEXT) RETURNS TEXT
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN spdx_id IS NULL THEN 'uncategorized'
        WHEN spdx_id IN (
            'GPL-2.0','GPL-2.0-only','GPL-2.0-or-later',
            'GPL-3.0','GPL-3.0-only','GPL-3.0-or-later',
            'AGPL-3.0','AGPL-3.0-only','AGPL-3.0-or-later',
            'SSPL-1.0','EUPL-1.2'
        ) THEN 'copyleft'
        WHEN spdx_id IN (
            'LGPL-2.0','LGPL-2.0-only','LGPL-2.0-or-later',
            'LGPL-2.1','LGPL-2.1-only','LGPL-2.1-or-later',
            'LGPL-3.0','LGPL-3.0-only','LGPL-3.0-or-later',
            'MPL-2.0','EPL-1.0','EPL-2.0','CDDL-1.0','CDDL-1.1'
        ) THEN 'weak-copyleft'
        ELSE 'permissive'
    END
$$;

-- +goose Down
DROP FUNCTION IF EXISTS license_category(TEXT);
