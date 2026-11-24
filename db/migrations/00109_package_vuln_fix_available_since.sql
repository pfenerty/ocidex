-- When a fix for a (package, vulnerability) mapping first became available:
-- the time the matcher first reported it fixed. The Workspace's waiting time
-- and per-CVE age read it; until now they could only use tag build dates.
--
-- A trigger rather than each writer's SQL: MergePackageVuln (the grype
-- refresher) and ReplacePackageVulns both write the table, and the rule is
-- the same for both. A mapping stays fixed from the first pass that saw it
-- fixed, so the refresher's update-in-place keeps the original time; a fix
-- that is withdrawn clears it. A row deleted and re-inserted (ReplacePackageVulns)
-- starts over, which is the most that path can know.
--
-- Fixed means fix_state 'fixed', or, on rows written before fix_state existed
-- (00075), a fixed version with no state.

-- +goose Up
ALTER TABLE package_vulnerability ADD COLUMN fix_available_since TIMESTAMPTZ;

COMMENT ON COLUMN package_vulnerability.fix_available_since IS
    'When the matcher first reported this mapping fixed. NULL while not fixed. Backfilled from updated_at, a lower bound on how long the fix has been out only in the sense that it is no earlier than the first pass that saw it.';

-- +goose StatementBegin
CREATE FUNCTION package_vuln_is_fixed(fix_state TEXT, fixed_version TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT COALESCE(fix_state = 'fixed', fixed_version IS NOT NULL AND fixed_version <> '')
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION package_vuln_track_fix() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT package_vuln_is_fixed(NEW.fix_state, NEW.fixed_version) THEN
    NEW.fix_available_since := NULL;
  ELSIF TG_OP = 'UPDATE' AND OLD.fix_available_since IS NOT NULL THEN
    NEW.fix_available_since := OLD.fix_available_since;
  ELSE
    NEW.fix_available_since := COALESCE(NEW.fix_available_since, now());
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER package_vuln_track_fix
    BEFORE INSERT OR UPDATE OF fix_state, fixed_version, fix_available_since ON package_vulnerability
    FOR EACH ROW EXECUTE FUNCTION package_vuln_track_fix();

-- Backfill: updated_at is the best signal rows written before this carry.
-- Idempotent, as it only fills rows still NULL.
UPDATE package_vulnerability
SET fix_available_since = updated_at
WHERE fix_available_since IS NULL
  AND package_vuln_is_fixed(fix_state, fixed_version);

-- +goose Down
DROP TRIGGER IF EXISTS package_vuln_track_fix ON package_vulnerability;
DROP FUNCTION IF EXISTS package_vuln_track_fix();
DROP FUNCTION IF EXISTS package_vuln_is_fixed(TEXT, TEXT);
ALTER TABLE package_vulnerability DROP COLUMN IF EXISTS fix_available_since;
