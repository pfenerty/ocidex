-- Identity moves off ocidex_user and onto its own table (ocidex-iqkt.1).
--
-- ocidex_user was GitHub-shaped from 00007: github_id BIGINT NOT NULL UNIQUE
-- was both the account's primary external key and its only one. That makes a
-- second issuer unrepresentable — an account can hold exactly one GitHub id and
-- nothing else — and it leaks the provider's name into every reader of the row.
--
-- user_identity holds the (provider, subject) pairs an account may sign in
-- with, one row per issuer. 'github' keeps its own name rather than becoming
-- 'oidc:github' because GitHub is not an OIDC issuer here: it is exchanged
-- through the plain OAuth2 user API, and the subject is its numeric user id as
-- text. Generic issuers are namespaced 'oidc:<name>' so two deployments'
-- issuers cannot collide on a bare subject.
--
-- email and display_name land on ocidex_user because they are properties of the
-- account, not of the credential used to reach it: linking a second identity in
-- ocidex-iqkt.2 must not change who the account displays as.
--
-- github_id and github_username are kept, nullable, for one release. Every
-- reader still reads them (nothing has moved yet), and a rollback to the
-- previous binary between this migration and ocidex-iqkt.5 must not strand live
-- sessions. They are dropped in ocidex-iqkt.5, together with 00008's
-- bootstrap-by-github_id, which needs a (provider, subject) equivalent first.

-- +goose Up
CREATE TABLE user_identity (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES ocidex_user(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,  -- 'github' | 'oidc:<name>'
    subject    TEXT NOT NULL,  -- the provider's stable subject for this account
    email      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);
CREATE INDEX ON user_identity (user_id);

COMMENT ON COLUMN user_identity.provider IS
    'Issuer key: ''github'' for the GitHub OAuth2 app, ''oidc:<name>'' for a configured OIDC issuer.';
COMMENT ON COLUMN user_identity.subject IS
    'The issuer''s stable subject. GitHub''s numeric user id as text, or the OIDC ID token ''sub'' claim.';

INSERT INTO user_identity (user_id, provider, subject)
SELECT id, 'github', github_id::text FROM ocidex_user;

ALTER TABLE ocidex_user
    ADD COLUMN email        TEXT,
    ADD COLUMN display_name TEXT;

UPDATE ocidex_user SET display_name = github_username;

ALTER TABLE ocidex_user
    ALTER COLUMN github_id       DROP NOT NULL,
    ALTER COLUMN github_username DROP NOT NULL;

-- +goose Down
-- Lossy, deliberately. github_id is NOT NULL UNIQUE on the way back, and an
-- account created through a non-GitHub issuer has no value that could satisfy
-- it — there is nothing to synthesize. Such accounts are deleted, cascading to
-- their sessions, API keys and namespace memberships. This is a down-migration
-- for an unreleased forward step, not a rollback plan for a deployment that has
-- already signed users in through OIDC.
DELETE FROM ocidex_user WHERE github_id IS NULL OR github_username IS NULL;

ALTER TABLE ocidex_user
    ALTER COLUMN github_id       SET NOT NULL,
    ALTER COLUMN github_username SET NOT NULL;

ALTER TABLE ocidex_user
    DROP COLUMN display_name,
    DROP COLUMN email;

DROP TABLE user_identity;
