-- +goose Up
-- The file a component was read from (ADR-048 R6).
--
-- Syft emits syft:location:0:path beside the syft:location:0:layerID this table
-- has stored since 00046. It is what distinguishes the twelve commands built
-- from one Go module: a scanner sees them all as
-- pkg:golang/github.com/pfenerty/ocidex, and only the binary's filename says
-- which one an image actually ships.
--
-- Nullable and left empty here. cmd/backfill-provenance fills existing rows
-- from raw_bom; until it runs those components match nothing under R6, which
-- is the status quo rather than a wrong answer (ADR-048 R7).
ALTER TABLE component ADD COLUMN file_path TEXT;

-- +goose Down
ALTER TABLE component DROP COLUMN IF EXISTS file_path;
