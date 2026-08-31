-- The GitHub-shaped columns leave ocidex_user (ocidex-iqkt.5).
--
-- 00069 moved identity onto user_identity and kept github_id/github_username
-- nullable for one release, so a rollback to the previous binary could still
-- find accounts created in the meantime. That window is over: nothing above the
-- repository has read either column since ocidex-iqkt.2, and leaving them would
-- keep one issuer's name in the schema of a table that is now issuer-agnostic.
--
-- 00007 and 00008 are deliberately left alone. They are consistent at their own
-- point in history — 00008 seeds the bootstrap admin by github_id into a table
-- that still has the column, and 00069's backfill turns that row into a
-- ('github', '16961380') identity before this migration runs — so a fresh
-- database replays the whole sequence and arrives at the same place as an
-- upgraded one. Rewriting an applied migration to say something it never said
-- would buy nothing and break that equivalence.

-- +goose Up
ALTER TABLE ocidex_user
    DROP COLUMN github_id,
    DROP COLUMN github_username;

-- +goose Down
-- Lossy in the same way 00069's down step is. The columns come back nullable
-- and are refilled from the github identities that survive; an account that
-- only ever signed in through OIDC gets NULLs, because there is no GitHub id to
-- synthesize. Restoring NOT NULL UNIQUE would mean deleting those accounts, and
-- 00069's down step is where that decision is already made and documented.
ALTER TABLE ocidex_user
    ADD COLUMN github_id BIGINT,
    ADD COLUMN github_username TEXT;

UPDATE ocidex_user u
SET github_id = i.subject::bigint,
    github_username = u.display_name
FROM user_identity i
WHERE i.user_id = u.id
  AND i.provider = 'github'
  AND i.subject ~ '^[0-9]+$';
