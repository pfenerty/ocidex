---
status: "proposed"
date: 2026-10-15
decision-makers: Patrick Fenerty
---

# Application-level encryption of stored registry credentials

## Context and Problem Statement

`registry.auth_token` (migration 00014) and `registry.webhook_secret` (00009) are
plaintext `TEXT`. Anyone holding a database dump, a replica, a CNPG backup or a
`psql` session reads every registry credential users have entrusted to OCIDex.

Neither can be hashed. The scanner, the OCI-metadata and provenance enrichers and the
cluster-ingest path present `auth_token` to the registry, so they need the plaintext.
`GET`/`POST /registries/{id}/webhook-secret` return the webhook secret to holders of
`read_secret` (ADR-046), so the server must be able to recover it too.

How should OCIDex keep these values unreadable at rest while every process that
legitimately needs them can still use them?

### Audit of secret-bearing columns

Every column in `db/migrations/` that holds or derives from a secret:

| Column | Stored as | In scope |
|---|---|---|
| `registry.auth_token` | plaintext | **yes** — encrypted by this ADR |
| `registry.webhook_secret` | plaintext | **yes** — encrypted by this ADR |
| `session.token_hash` | hex(SHA-256(token)) | no — already a one-way hash; the raw token is never stored |
| `api_key.key_hash` | hex(SHA-256(key)) | no — already a one-way hash. `api_key.prefix` is the first 8 characters, for display; it is not enough to authenticate |
| `registry.trust_public_key` | PEM public key | no — public by definition |
| `user_identity.subject`, `.email` | plaintext | no — identifiers, not credentials (ADR-047) |
| `enrichment_jobs.idempotency_key` | plaintext | no — a dedup key, not a secret |

Cluster agents authenticate with API keys (`api_key.key_hash`), so there is no separate
cluster push-token column. OAuth/OIDC client secrets and `SESSION_SECRET` live in the
environment, never in the database.

## Decision Drivers

* A database-only compromise (dump, replica, backup) must not yield usable credentials.
* No new third-party dependency, and no new infrastructure an operator must run.
* No schema change: existing `TEXT` columns, existing queries, existing sqlc types.
* Existing installations upgrade without re-entering credentials.
* Keys must be rotatable without downtime.
* A ciphertext copied from one row or column to another must not decrypt there.

## Considered Options

* Application-level envelope encryption with stdlib AES-256-GCM
* `pgcrypto` (`pgp_sym_encrypt` in SQL)
* An external KMS or Vault transit engine
* Hashing the webhook secret

## Decision Outcome

Chosen option: "Application-level encryption with stdlib AES-256-GCM", because it is
the only option that protects against a database-only compromise without new
infrastructure or dependencies, and it leaves room for a KMS behind the same interface.

### Algorithm

AES-256-GCM via `crypto/aes` + `crypto/cipher`. A fresh random 96-bit nonce from
`crypto/rand` per encryption. The additional authenticated data (AAD) is
`<table>.<column>:<row id>`, e.g. `registry.auth_token:6f1c…`, so a ciphertext moved to
another row or another column fails authentication instead of decrypting.

Binding to the row id means the id must be known before the row is written.
`CreateRegistry` takes the id from the caller instead of generating it in SQL.

### Stored format

```
enc:v1:<key-id>:<base64std(nonce || ciphertext || tag)>
```

The value goes in the existing `TEXT` column. `v1` names this format; a future format
gets `v2`. `<key-id>` names the key that encrypted the value, which is what makes
rotation possible. A key id is `[A-Za-z0-9_-]{1,32}`, so it cannot contain `:`.

A value without the `enc:v1:` prefix is **legacy plaintext**: it is returned as-is,
flagged as legacy, so pre-upgrade rows keep working until they are re-encrypted. A
value with an `enc:` prefix that fails to parse or authenticate is an error, never
passed through. A credential a user could legitimately type that begins with `enc:v1:`
would be misread, and is accepted as a known, negligible limitation.

### Keys

```
DATA_ENCRYPTION_KEYS=<id>:<base64 32 bytes>[,<id>:<base64 32 bytes>...]
DATA_ENCRYPTION_ACTIVE_KEY=<id>
```

New values are encrypted with the active key. Every listed key can decrypt, so rotation
is: add the new key, make it active, run the re-encrypt command, then remove the old
key. A malformed list, a key that is not exactly 32 bytes, a duplicate id, or an active
id not in the list is a startup error. Generate a key with `openssl rand -base64 32`.

### Rollout rule

* `ENVIRONMENT=production` without `DATA_ENCRYPTION_KEYS` is a **startup error** in
  every process that loads `config.Config`. Losing credential protection silently is
  the failure this ADR exists to prevent.
* Outside production, no key means writes store plaintext and a warning is logged.
  Dev and test setups need no extra configuration. Reading an `enc:v1:` value without
  a key is still an error.
* `ocidex migrate encrypt-secrets` encrypts legacy plaintext and re-encrypts values
  under a non-active key. It is idempotent, supports `--dry-run`, and the chart runs it
  in the migrate hook Job after `migrate up`. A value it cannot decrypt (its key was
  removed) is reported and left alone rather than failing the hook, since the fix —
  re-entering the credential — needs the API running.

### Which processes need the key

The key goes to every process that reads or writes the two columns:

| Process | Why |
|---|---|
| `ocidex` (API) | writes both columns; webhook verification; `webhook-secret` endpoints; `migrate encrypt-secrets` |
| `scanner-worker` | claims scan jobs, which join `registry.auth_token`; catalog, size, metadata and cluster ingest |
| `oci-metadata-worker`, `provenance-worker` | `BuildCredentialLookup` presents `auth_token` to the registry |
| migrate hook Job | runs `ocidex migrate encrypt-secrets` after `migrate up` |

`git-worker`, `user-enricher-worker`, `vuln-worker`, the operator and the k8s agent
never read the columns. The operator writes credentials through the API, which
encrypts. Ephemeral scans (ADR-027) take `SCAN_AUTH_TOKEN` from the environment of
whoever launches them, never from the database, and NATS carries only job hints, never
credentials.

The chart already mounts one `existingSecret` into every workload with `envFrom`
(DEPLOYMENT.md, "Secret material"). The two keys are added to that Secret. Processes
that do not need them ignore them.

### Interface

`internal/secretbox` exposes a `Box` with `Encrypt(plaintext, aad []byte) (string, error)`
and `Decrypt(stored string, aad []byte) ([]byte, bool, error)`, the bool reporting
legacy plaintext. Encryption happens in the service layer: repositories keep moving
opaque strings, and the API layer only ever sees plaintext. A KMS-backed key ring can
replace the static one later without touching callers.

### Consequences

* Good, because a dump, replica or backup no longer leaks registry credentials.
* Good, because no dependency, no schema change, and no new service to operate.
* Good, because rotation is an online operation.
* Bad, because the key lives in the same cluster as the database. An attacker with
  both the database and the `ocidex-secrets` Secret still wins. This defends against
  database-only exposure, which is the common case (backups, replicas, support dumps).
* Bad, because losing every key makes the stored credentials unrecoverable: users must
  re-enter them. Operations must back up the key separately from the database.
* Bad, because a production upgrade without a key fails to start. The upgrade note
  must say so.

### Confirmation

* Unit tests in `internal/secretbox`: round trip, wrong AAD, tampered ciphertext,
  unknown key id, rotation, legacy passthrough, malformed key config.
* An integration test asserts the `registry.auth_token` column does not hold the
  plaintext after a create, and that `encrypt-secrets` is idempotent.

## Pros and Cons of the Options

### Application-level AES-256-GCM

* Good, because stdlib-only and auditable in one small package.
* Good, because the database never sees a key or a plaintext.
* Bad, because every reader of the columns must go through the service layer, and a
  query that bypasses it returns ciphertext.

### pgcrypto

* Good, because transparent to Go code.
* Bad, because the key travels in every SQL statement or session setting, where it
  can land in `pg_stat_statements`, logs and the very backups this is meant to
  protect.
* Bad, because it requires the extension in every Postgres deployment.

### External KMS or Vault

* Good, because the key never leaves the KMS.
* Bad, because it adds required infrastructure to a self-hosted product, and a network
  call per decrypt.
* Neutral, because it is a future key-ring provider behind the same `Box` interface,
  not an alternative to it.

### Hashing the webhook secret

* Bad, because impossible: `read_secret` holders retrieve the secret, so the server
  must be able to recover it. It would also do nothing for `auth_token`.

## More Information

* ADR-046 — the `read_secret` capability that returns the webhook secret.
* ADR-027 — the ephemeral job contract that carries `SCAN_AUTH_TOKEN`.
* Epic `ocidex-d90k`.
