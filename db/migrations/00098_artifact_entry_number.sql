-- +goose Up
-- A short, sequential number per artifact in the order it was first indexed,
-- shown as "№ 012" and resolvable from search as "#12". The UUID stays the
-- identity; this is a label people can say out loud. Numbers are never reused:
-- a deleted artifact leaves a gap.
ALTER TABLE artifact ADD COLUMN entry_number BIGINT;

UPDATE artifact a
SET entry_number = n.rn
FROM (SELECT id, ROW_NUMBER() OVER (ORDER BY created_at, id) AS rn FROM artifact) n
WHERE a.id = n.id;

CREATE SEQUENCE artifact_entry_number_seq OWNED BY artifact.entry_number;
SELECT setval('artifact_entry_number_seq', COALESCE((SELECT MAX(entry_number) FROM artifact), 0) + 1, false);

ALTER TABLE artifact ALTER COLUMN entry_number SET DEFAULT nextval('artifact_entry_number_seq');
ALTER TABLE artifact ALTER COLUMN entry_number SET NOT NULL;
CREATE UNIQUE INDEX idx_artifact_entry_number ON artifact (entry_number);

-- +goose Down
DROP INDEX idx_artifact_entry_number;
ALTER TABLE artifact DROP COLUMN entry_number;
