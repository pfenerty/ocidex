-- +goose Up
-- ADR-0053: each registry keeps only the newest tag_limit tags per repository,
-- ordered by tag_order. Existing registries get the default of 50 too, which
-- stops their backfill on the next poll; SBOMs already ingested outside the
-- window stay until retention removes them.
ALTER TABLE registry ADD COLUMN tag_limit INTEGER NOT NULL DEFAULT 50 CHECK (tag_limit >= 0);
-- NULL = auto: semver when tag_patterns contains 'semver', created otherwise.
ALTER TABLE registry ADD COLUMN tag_order TEXT CHECK (tag_order IN ('semver', 'created', 'lexical'));
-- Only meaningful when the effective order is created; the API enforces that.
ALTER TABLE registry ADD COLUMN max_tag_age_days INTEGER CHECK (max_tag_age_days >= 1);

-- +goose Down
ALTER TABLE registry DROP COLUMN max_tag_age_days;
ALTER TABLE registry DROP COLUMN tag_order;
ALTER TABLE registry DROP COLUMN tag_limit;
