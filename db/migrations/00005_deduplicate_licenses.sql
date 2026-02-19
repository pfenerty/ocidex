-- +goose Up

-- Temporary table with alias → SPDX mappings for deduplication.
CREATE TEMPORARY TABLE license_alias (
    alias_name TEXT NOT NULL,
    spdx_id    TEXT NOT NULL,
    display    TEXT NOT NULL
);

INSERT INTO license_alias (alias_name, spdx_id, display) VALUES
    ('mit license',              'MIT',              'MIT License'),
    ('the mit license',          'MIT',              'MIT License'),
    ('apache 2.0',               'Apache-2.0',       'Apache License 2.0'),
    ('apache license 2.0',       'Apache-2.0',       'Apache License 2.0'),
    ('apache-2',                 'Apache-2.0',       'Apache License 2.0'),
    ('asl 2.0',                  'Apache-2.0',       'Apache License 2.0'),
    ('apache 2',                 'Apache-2.0',       'Apache License 2.0'),
    ('gplv2',                    'GPL-2.0-only',     'GNU General Public License v2.0 only'),
    ('gpl-2',                    'GPL-2.0-only',     'GNU General Public License v2.0 only'),
    ('gpl 2',                    'GPL-2.0-only',     'GNU General Public License v2.0 only'),
    ('gpl-2.0',                  'GPL-2.0-only',     'GNU General Public License v2.0 only'),
    ('gplv2+',                   'GPL-2.0-or-later', 'GNU General Public License v2.0 or later'),
    ('gpl-2.0+',                 'GPL-2.0-or-later', 'GNU General Public License v2.0 or later'),
    ('gpl-2+',                   'GPL-2.0-or-later', 'GNU General Public License v2.0 or later'),
    ('gpl 2+',                   'GPL-2.0-or-later', 'GNU General Public License v2.0 or later'),
    ('gpl-2-or-later',           'GPL-2.0-or-later', 'GNU General Public License v2.0 or later'),
    ('gplv3',                    'GPL-3.0-only',     'GNU General Public License v3.0 only'),
    ('gpl-3',                    'GPL-3.0-only',     'GNU General Public License v3.0 only'),
    ('gpl 3',                    'GPL-3.0-only',     'GNU General Public License v3.0 only'),
    ('gpl-3.0',                  'GPL-3.0-only',     'GNU General Public License v3.0 only'),
    ('gplv3+',                   'GPL-3.0-or-later', 'GNU General Public License v3.0 or later'),
    ('gpl-3.0+',                 'GPL-3.0-or-later', 'GNU General Public License v3.0 or later'),
    ('gpl-3+',                   'GPL-3.0-or-later', 'GNU General Public License v3.0 or later'),
    ('gpl 3+',                   'GPL-3.0-or-later', 'GNU General Public License v3.0 or later'),
    ('gpl-3-or-later',           'GPL-3.0-or-later', 'GNU General Public License v3.0 or later'),
    ('gpl',                      'GPL-2.0-or-later', 'GNU General Public License v2.0 or later'),
    ('lgpl',                     'LGPL-2.1-or-later','GNU Lesser General Public License v2.1 or later'),
    ('lgplv2',                   'LGPL-2.0-only',    'GNU Library General Public License v2 only'),
    ('lgpl-2',                   'LGPL-2.0-only',    'GNU Library General Public License v2 only'),
    ('lgpl-2.0',                 'LGPL-2.0-only',    'GNU Library General Public License v2 only'),
    ('lgplv2.1',                 'LGPL-2.1-only',    'GNU Lesser General Public License v2.1 only'),
    ('lgpl-2.1',                 'LGPL-2.1-only',    'GNU Lesser General Public License v2.1 only'),
    ('lgplv3',                   'LGPL-3.0-only',    'GNU Lesser General Public License v3.0 only'),
    ('lgpl-3',                   'LGPL-3.0-only',    'GNU Lesser General Public License v3.0 only'),
    ('lgpl-3.0',                 'LGPL-3.0-only',    'GNU Lesser General Public License v3.0 only'),
    ('agplv3',                   'AGPL-3.0-only',    'GNU Affero General Public License v3.0'),
    ('agpl-3',                   'AGPL-3.0-only',    'GNU Affero General Public License v3.0'),
    ('agpl-3.0',                 'AGPL-3.0-only',    'GNU Affero General Public License v3.0'),
    ('bsd',                      'BSD-3-Clause',     'BSD 3-Clause License'),
    ('bsd license',              'BSD-3-Clause',     'BSD 3-Clause License'),
    ('bsd-3',                    'BSD-3-Clause',     'BSD 3-Clause License'),
    ('bsd 3-clause',             'BSD-3-Clause',     'BSD 3-Clause License'),
    ('bsd-2',                    'BSD-2-Clause',     'BSD 2-Clause "Simplified" License'),
    ('bsd 2-clause',             'BSD-2-Clause',     'BSD 2-Clause "Simplified" License'),
    ('mpl',                      'MPL-2.0',          'Mozilla Public License 2.0'),
    ('mpl-2',                    'MPL-2.0',          'Mozilla Public License 2.0'),
    ('mpl 2.0',                  'MPL-2.0',          'Mozilla Public License 2.0'),
    ('isc license',              'ISC',              'ISC License'),
    ('zlib license',             'Zlib',             'zlib License'),
    ('zlib',                     'Zlib',             'zlib License'),
    ('boost',                    'BSL-1.0',          'Boost Software License 1.0'),
    ('boost software license',   'BSL-1.0',          'Boost Software License 1.0'),
    ('bsl-1.0',                  'BSL-1.0',          'Boost Software License 1.0'),
    ('public domain',            'Unlicense',        'The Unlicense'),
    ('public-domain',            'Unlicense',        'The Unlicense'),
    ('publicdomain',             'Unlicense',        'The Unlicense');

-- Step 1: For each alias-matched non-SPDX license, ensure a canonical SPDX row exists.
INSERT INTO license (spdx_id, name)
SELECT DISTINCT la.spdx_id, la.display
FROM license l
JOIN license_alias la ON lower(trim(l.name)) = la.alias_name
WHERE l.spdx_id IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM license canon WHERE canon.spdx_id = la.spdx_id
  )
ON CONFLICT DO NOTHING;

-- Step 2: Re-point component_license rows from variant licenses to canonical ones.
-- Skip rows where the component already has the canonical license to avoid PK violations.
UPDATE component_license cl
SET license_id = canon.id
FROM license old
JOIN license_alias la ON lower(trim(old.name)) = la.alias_name
JOIN license canon ON canon.spdx_id = la.spdx_id AND canon.id <> old.id
WHERE cl.license_id = old.id
  AND old.spdx_id IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM component_license dup
      WHERE dup.component_id = cl.component_id AND dup.license_id = canon.id
  );

-- Step 3: Delete component_license rows that are now duplicates (variant still pointed at old).
DELETE FROM component_license cl
USING license old
JOIN license_alias la ON lower(trim(old.name)) = la.alias_name
WHERE cl.license_id = old.id
  AND old.spdx_id IS NULL
  AND EXISTS (
      SELECT 1 FROM license canon
      WHERE canon.spdx_id = la.spdx_id AND canon.id <> old.id
  );

-- Step 4: Delete orphaned non-SPDX license rows with no remaining component_license references.
DELETE FROM license l
USING license_alias la
WHERE lower(trim(l.name)) = la.alias_name
  AND l.spdx_id IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM component_license cl WHERE cl.license_id = l.id
  );

DROP TABLE license_alias;

-- +goose Down
-- This migration merges license rows; reversal would require restoring
-- the original non-SPDX rows and re-pointing component_license, which
-- is not safely automatable. Manual intervention required.
SELECT 'down migration for 00005_deduplicate_licenses is a no-op; manual restore needed';
