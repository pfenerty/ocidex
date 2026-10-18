-- Remove the account 00008 seeded when nobody has used it (ocidex-7tss).
--
-- 00008 put GitHub user 16961380 (the maintainer) into every database, and
-- 00079 demoted it to viewer. That still leaves every fresh install with one
-- pre-provisioned account a third party can sign in to, ahead of the
-- operator, before anything else exists.
--
-- 00008 and 00079 stay as written (00070's header explains why). This deletes
-- the row only while it is still the untouched seed. Every condition errs
-- toward keeping it:
--   - its identity has never been updated: every sign-in rewrites
--     user_identity.updated_at (UpsertIdentityEmail), and expired sessions are
--     purged, so this is the one lasting record of a sign-in;
--   - no email on the account, and no second identity linked to it;
--   - nothing hangs off it: no session, API key, namespace membership or
--     watch. Those rows cascade, so this also makes the delete lose nothing.
-- An install where the account was ever used keeps it, role and all.

-- +goose Up
DELETE FROM ocidex_user u
USING user_identity i
WHERE i.user_id = u.id
  AND i.provider = 'github'
  AND i.subject = '16961380'
  AND i.updated_at = i.created_at
  AND i.email IS NULL
  AND u.email IS NULL
  AND NOT EXISTS (SELECT 1 FROM user_identity o WHERE o.user_id = u.id AND o.id <> i.id)
  AND NOT EXISTS (SELECT 1 FROM session s WHERE s.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM api_key k WHERE k.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM namespace_member m WHERE m.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM artifact_watch w WHERE w.user_id = u.id);

-- +goose Down
-- Restores the seed as 00079 left it, if no account holds the identity.
-- +goose StatementBegin
WITH seed AS (
    INSERT INTO ocidex_user (role, display_name)
    SELECT 'viewer', 'pfenerty'
    WHERE NOT EXISTS (
        SELECT 1 FROM user_identity WHERE provider = 'github' AND subject = '16961380'
    )
    RETURNING id
)
INSERT INTO user_identity (user_id, provider, subject)
SELECT id, 'github', '16961380' FROM seed;
-- +goose StatementEnd
