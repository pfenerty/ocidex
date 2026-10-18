# Upgrading OCIDex

How to move a deployment from one release to the next, and what to do when that goes wrong.
The compatibility promises behind this guide are in
[ADR-052](adr/0052-v1-compatibility.md). For what changed in a release, see
[CHANGELOG.md](../CHANGELOG.md). Anything you must **do** to upgrade is written here.

## Supported upgrade paths

| From | To | Path |
|---|---|---|
| Any 1.x | Any later 1.x | Direct. No intermediate stops. |
| Latest 0.x minor | 1.0 | Direct. |
| Older 0.x | 1.0 | Upgrade to the latest 0.x minor first, then to 1.0. |
| Any version | An older version | Not supported as an upgrade. Restore a backup instead (see [Rolling back](#rolling-back)). |

The API, the scanner worker, every enricher worker and the vuln worker must run the **same
version**. A mixed-version deployment is only supported for the duration of a rolling upgrade.

## Before every upgrade

1. **Read this release's section** under [Per-version notes](#per-version-notes). Do any
   step marked *before upgrading* first. Some of them stop the new version from starting if
   they are skipped.
2. **Back up the database.** Rollback means restoring this backup (see
   [Rolling back](#rolling-back)). With CloudNativePG, take an on-demand `Backup` of the
   `ocidex-pg` cluster and wait until its phase is `completed`. Without CNPG, take a
   `pg_dump --format=custom` as the app role. Back up the `existingSecret` too, including
   `DATA_ENCRYPTION_KEYS`. A database restored without its encryption keys has unreadable
   registry credentials.
3. **Note the current chart revision** (`helm history <release> -n <ns>`) so you know
   what to roll back to.

## What happens during an upgrade

Database migrations run before any new pod serves traffic:

- With the chart, the migrate Job is a `pre-install,pre-upgrade` Helm hook (see
  [DEPLOYMENT.md § migrate Job](DEPLOYMENT.md#ocidex-dev-migrate-job-helm-hook-on-every-install-and-upgrade)).
  An init container runs `ocidex migrate up`, then `ocidex migrate encrypt-secrets` runs.
  Deployments are updated only after the Job succeeds.
- Without the chart, run `ocidex migrate up` with the **new** binary before you replace the
  running processes, then run `ocidex migrate encrypt-secrets`.

Migrations are forward-only as a supported path. Each one runs in its own transaction, so a
failure leaves the schema at the last migration that succeeded. The exception is index
builds marked `NO TRANSACTION` (`CREATE INDEX CONCURRENTLY`, for example 00078). A failure
there can leave an `INVALID` index behind. Drop it before you retry.

### If the migrate Job fails

- The Helm upgrade fails and the Deployments are **not** updated. The previous version keeps
  serving. Whether it still works against a partly migrated schema depends on how far the
  migration got, so fix the cause promptly.
- Read the Job's logs: `kubectl -n <ns> logs job/<release>-migrate-<revision> --all-containers`.
  Pods are reaped a few minutes after a failure. If the logs are gone,
  `ocidex migrate audit` in a throwaway pod reproduces the ownership preflight read-only.
- Common causes are listed in
  [DEPLOYMENT.md § Troubleshooting](DEPLOYMENT.md#troubleshooting): the `DATABASE_URL`
  shape, CNPG not yet `Ready`, objects owned by another role (the Job prints the
  `ALTER ... OWNER TO` statements to run), or missing encryption keys.
- After fixing the cause, run the same upgrade again. `migrate up` resumes from where it
  stopped.

## Rolling back

**The supported rollback is restoring the pre-upgrade backup and redeploying the previous
version.**

1. Scale every OCIDex Deployment to zero, or suspend the Flux `HelmRelease`.
2. Restore the database from the backup taken in [Before every upgrade](#before-every-upgrade).
   With CNPG, bootstrap a new cluster from the backup with `recovery` and point
   `DATABASE_URL` at it.
3. Redeploy the previous version: `helm rollback <release> <revision> -n <ns>`, or pin the
   previous chart version in the `HelmRelease` (see
   [DEPLOYMENT.md](DEPLOYMENT.md) for the Flux pin procedure).

Anything ingested after the backup is lost, so re-push those SBOMs or re-run the scans.

A chart rollback alone (`helm rollback` or a Flux pin) does **not** roll back migrations.
Migrations add columns and tables more often than they remove them, so the previous version
usually runs against the newer schema. Only rely on that when the release's notes below say
so.

`ocidex migrate down` exists for development. It is not a supported rollback, because
several down steps lose data on purpose:

- **00069** deletes every account that signed in only through a non-GitHub issuer.
- **00070** restores the GitHub columns as nullable and refills them only from surviving
  GitHub identities.

## Operator CRDs

The operator chart (`charts/ocidex-operator`) is **alpha** and has no compatibility
guarantee (ADR-052). Its CRDs are in the chart's `crds/` directory, and **Helm installs
them but never upgrades them**.

- **Flux:** set `install.crds: CreateReplace` **and** `upgrade.crds: CreateReplace` on the
  `HelmRelease`, and Flux applies CRD changes on every upgrade.
- **Helm CLI:** apply the CRDs from the new chart before upgrading the release:

  ```bash
  helm pull oci://ghcr.io/pfenerty/charts/ocidex-operator --version <new> --untar
  kubectl apply --server-side -f ocidex-operator/crds/
  helm upgrade ocidex-operator oci://ghcr.io/pfenerty/charts/ocidex-operator --version <new> ...
  ```

A CRD version change (for example `v1alpha1` to `v1beta1`) gets its own migration note below.

## Per-version notes

Newest first. Each entry names the issue that made the change, so its full context is in
`bd show <id>`.

### Next release (unreleased)

**Behavior changes to check after upgrading:**

- **Registry responses no longer carry `owner_id` or `owner_username` (ocidex-bt62.2).** A
  registry has no owner of its own; it belongs to a namespace (ADR-039, ADR-046). The two
  fields only repeated the namespace's owner member, and only the list endpoint filled in
  `owner_username`. Read the owner from the registry's namespace
  (`GET /api/v1/namespaces/{id}`, `owner_id` / `owner_username`). `/api/v1/users/me/registries`
  still lists registries in namespaces you own.

- **The account migration 00008 seeded is removed if it was never used (ocidex-7tss).**
  Migration 00080 deletes the GitHub `16961380` account (a viewer since 0.1.0) unless it
  has ever signed in or has a session, API key, namespace membership, watch, email or
  second identity. A fresh install now starts with no accounts. If the account was used
  on your install, nothing changes.

**After upgrading:**

- **Run `ocidex migrate backfill` once if your database predates 0.1.0's data (ocidex-bt62.1).**
  The one-shot `backfill-flavor`, `backfill-component-purl` and `backfill-provenance` binaries
  are gone, and `ocidex migrate backfill` replaces them. It fills the columns ingest now writes for
  rows stored before it did: an SBOM's flavor, a component's purl version (until then the
  component is never vulnerability-scanned), and component provenance plus `file_path` (until
  then ADR-048 command relationships miss those SBOMs). It is idempotent and a no-op on a
  fresh install. It reads every affected SBOM's `raw_bom`, so it is not part of the chart's
  migrate hook. See [OPERATIONS.md](OPERATIONS.md) "Backfilling rows stored before ingest
  derived them".

### 0.1.0

**Before upgrading:**

- **Add the credential encryption keys (ocidex-d90k, ADR-051).** Add
  `DATA_ENCRYPTION_KEYS=<id>:<base64 32 bytes>` and `DATA_ENCRYPTION_ACTIVE_KEY=<id>` to
  the chart's `existingSecret`. With `ENVIRONMENT=production` (the chart default), the API,
  the scanner worker, the enrichers and the migrate Job refuse to start without them.
  Generate a key with `openssl rand -base64 32` and back it up separately from the
  database. Losing it means re-entering every registry credential. The migrate hook runs
  `ocidex migrate encrypt-secrets` after `migrate up` and encrypts existing plaintext.
  Plaintext rows keep working until it runs. See
  [OPERATIONS.md](OPERATIONS.md) "Rotating the credential encryption key".
- **Set `BOOTSTRAP_ADMINS` (ocidex-avsz.1).** Migration 00008 made GitHub user `16961380`
  an installation admin in every database. Migration 00079 demotes that account to `viewer`
  unless it has a session or an API key. The first admin now comes from `BOOTSTRAP_ADMINS`
  (chart: `api.env.bootstrapAdmins`) and is promoted at sign-in. Set it **before**
  upgrading if you sign in as that account, or as any other admin you still need. See
  [CONFIGURATION.md](CONFIGURATION.md#first-admin).
- **Cross-site SPA deployments: set `SESSION_COOKIE_SAMESITE=none` (ocidex-mqav.2).** The
  session cookie is now `SameSite=Lax` in production. It was `SameSite=None`. Lax works
  whenever the SPA and the API share a registrable domain. If you serve the SPA from a
  **different** registrable domain, set `SESSION_COOKIE_SAMESITE=none` (chart:
  `api.env.sessionCookieSameSite`), or every API call from the SPA arrives without its
  session.
- **Scanning a registry on a private network: set the egress policy (ocidex-avsz.5,
  .6, .7).** The API, `scanner-worker` and the enricher workers now refuse to dial private
  addresses (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`), loopback,
  link-local (including cloud metadata) and multicast. That covers an in-cluster or LAN
  registry such as zot or Harbor. Its scans fail as permanent errors, and the API rejects an
  ingested SBOM naming an image there with 400. Before upgrading, allow just that registry's
  address with `EGRESS_ALLOW_CIDRS` (chart: `egressGuard.allowCidrs`), or all private ranges
  with `EGRESS_ALLOW_PRIVATE=true` (chart: `egressGuard.allowPrivate`). Set the same values
  on every component; the chart does. See
  [CONFIGURATION.md](CONFIGURATION.md#egress-policy).
- **`CORS_ALLOWED_ORIGINS` must be exact origins in production (ocidex-mqav.3).** With
  `ENVIRONMENT=production`, the API refuses to start if `CORS_ALLOWED_ORIGINS` contains
  `*`, or any entry that isn't `scheme://host[:port]` (http or https, with no path,
  trailing `/`, credentials, query or fragment). Check the value before upgrading.
- **Behind an ingress: set `TRUSTED_PROXY_CIDRS` (ocidex-mqav.5).** Sign-in endpoints are
  rate-limited per client IP: 30 requests per minute by default (`AUTH_RATE_LIMIT`, chart
  `api.env.authRateLimit`; `0` disables). Set `TRUSTED_PROXY_CIDRS` (chart
  `api.env.trustedProxyCidrs`) to the ingress's address range, or every visitor shares the
  ingress's budget.

**Behavior changes to check after upgrading:**

- **Cookie-authenticated writes must come from a trusted origin (ocidex-mqav.1).** A
  `POST`, `PUT`, `PATCH` or `DELETE` that authenticates by session cookie is refused with
  403 unless its `Origin` (or `Referer`) is one of:
  - in `CORS_ALLOWED_ORIGINS`;
  - `FRONTEND_URL`, when `CORS_ALLOWED_ORIGINS` is unset;
  - the API's own origin (`API_BASE_URL`).

  API-key clients are unaffected.
- **SBOM ingest and the expensive reads are rate-limited per principal (ocidex-mqav.6).**
  The default is 120 requests per minute each (`API_RATE_LIMIT_INGEST`,
  `API_RATE_LIMIT_HEAVY`; `0` disables). No role is exempt, so raise the ingest limit if a
  CI or operator key pushes faster.
- **Registry URLs are validated on create and update (ocidex-avsz.8).** A registry `url`
  must be `host[:port]` (or `http(s)://host[:port]`). Credentials, a path, a query or a
  fragment are rejected with 422, and so is an IP address the egress policy refuses.
  Registries created before the upgrade keep working, but editing one with such a URL fails
  until the URL is fixed. Put repositories in `repositories`, not in the path, and
  credentials in `auth_username` / `auth_token`.
- **Attaching a new registry to an existing namespace needs `manage_source` there
  (ocidex-avsz.2).** `POST /api/v1/registries` with a `namespace` that already exists now
  returns 404 to non-members and 403 to members without `manage_source`, instead of
  attaching the registry. Naming a new namespace still creates it.
- **The web UI sends a strict Content-Security-Policy (ocidex-mqav.7, .9).** The bundled
  nginx sets `frame-ancestors 'none'`, so the UI can no longer be embedded in an iframe.
  Scripts and styles load only from the UI's origin, plus Google Fonts. A proxy that injects
  scripts or inline styles into the UI's pages will have them blocked.
- **New, optional: who may sign in and create namespaces (ocidex-avsz.4).** `SIGNUP_MODE`
  (default `open`, the previous behavior) and `SELF_SERVICE_NAMESPACES` (default `true`) let
  you limit sign-in to existing accounts and keep global viewers from creating namespaces.
  Nothing changes unless you set them. See
  [CONFIGURATION.md](CONFIGURATION.md#installation-policy).

**Chart rollback without a restore:** not safe for this release. Migration 00079 demotes the
seeded admin, and the previous version does not read `BOOTSTRAP_ADMINS`.

## Adding a note

Any change that an operator has to act on gets an entry under **Next release** in the same
PR. That includes:

- a new required setting, or a removed or renamed env var or chart value;
- a changed default;
- a migration that is lossy or slow;
- a CRD change.

At release time, rename the heading to the version and start a new empty **Next
release** section.
On every release, git-cliff output replaces the `[unreleased]` section of `CHANGELOG.md`, so
hand-written text there is lost.
