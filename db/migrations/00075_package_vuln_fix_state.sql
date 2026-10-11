-- The fix state grype reports per match (ADR-049): fixed, not-fixed, wont-fix, or
-- unknown. With fixed_version it distinguishes "upgrade to X" from "the distro
-- has decided not to fix this" and "no fix exists yet" — all three of which used
-- to read as a blank fixed version. NULL on rows written before this column (the
-- first full re-match fills it).

-- +goose Up
ALTER TABLE package_vulnerability ADD COLUMN fix_state TEXT;

-- +goose Down
ALTER TABLE package_vulnerability DROP COLUMN IF EXISTS fix_state;
