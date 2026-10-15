-- Demote the account 00008 seeded as installation admin (ocidex-avsz.1).
--
-- 00008 made GitHub user 16961380 (the maintainer) an admin in every database,
-- so every self-hosted install shipped with a stranger holding its keys. The
-- first admin now comes from BOOTSTRAP_ADMINS, promoted at sign-in.
--
-- 00008 itself stays as written (00070's header explains why). Instead the row
-- it seeded is demoted here — but only while it is still the untouched seed: an
-- account with a session or an API key has been signed in to, which means an
-- operator is relying on it. Those keep their role; the CHANGELOG upgrade note
-- tells such an operator to list the account in BOOTSTRAP_ADMINS, after which
-- either outcome converges.

-- +goose Up
UPDATE ocidex_user u
SET role = 'viewer',
    updated_at = now()
FROM user_identity i
WHERE i.user_id = u.id
  AND i.provider = 'github'
  AND i.subject = '16961380'
  AND u.role = 'admin'
  AND NOT EXISTS (SELECT 1 FROM session s WHERE s.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM api_key k WHERE k.user_id = u.id);

-- +goose Down
-- Restores 00008's end state. Lossy: an account that had been demoted by hand
-- after 00008 is promoted again, which is exactly what replaying 00008 did.
UPDATE ocidex_user u
SET role = 'admin',
    updated_at = now()
FROM user_identity i
WHERE i.user_id = u.id
  AND i.provider = 'github'
  AND i.subject = '16961380';
