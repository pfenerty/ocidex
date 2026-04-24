# Authorization Matrix

Every endpoint registered in `internal/api/router.go` as of 2026-04-24.

**Global middleware:** `OptionalAuthenticate` — attaches authenticated user to context when valid credentials are present, but **does not block unauthenticated requests**. Handlers are responsible for enforcing auth where required.

**Auth enforcement legend:**
- **Handler 401** — handler calls `UserFromContext` and returns 401 if no user
- **Handler 403** — handler checks role/ownership and returns 403 on mismatch
- **VisFilter** — no handler gate; SQL-layer `VisibilityFilter` restricts results to public data for unauthenticated callers
- **None** — no auth enforcement of any kind
- **Secret** — validated by webhook HMAC/bearer secret, not by user identity

---

## Health / Meta

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| GET | `/health` | None | — | — | — | Public liveness check |
| GET | `/ready` | None | — | — | — | Public readiness check |
| GET | `/api/v1/` | None | — | — | — | Public version info |

---

## Auth / Session

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| GET | `/auth/login` | None | — | — | — | Initiates OAuth flow |
| GET | `/auth/callback` | None | — | — | — | Completes OAuth flow |
| POST | `/auth/logout` | None | — | — | — | Clears session cookie; works unauthenticated |
| GET | `/api/v1/users/me` | Handler 401 | any | — | — | Returns own user record |
| POST | `/api/v1/auth/keys` | Handler 401 | admin \| member | — | — | Creates API key for self |
| GET | `/api/v1/auth/keys` | Handler 401 | admin \| member | Self only (service) | — | Lists own keys only |
| DELETE | `/api/v1/auth/keys/{id}` | Handler 401 | admin \| member | Self only (service) | — | Deletes own key only |
| GET | `/api/v1/users` | Handler 401 | admin | — | — | Lists all users |
| PATCH | `/api/v1/users/{id}/role` | Handler 401 | admin | — | — | Updates any user's role |
| GET | `/api/v1/admin/status` | Handler 401 | admin | — | — | System config/status |

---

## SBOMs

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| POST | `/api/v1/sboms` | **None** ⚠️ | — | — | — | **GAP: no auth check; anyone can ingest** |
| GET | `/api/v1/sboms` | None | — | — | SQL (service layer) | Unauthenticated sees public only |
| GET | `/api/v1/sboms/diff` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/sboms/{id}` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/sboms/{id}/dependencies` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/sboms/{id}/components` | None | — | — | SQL (service layer) | |
| DELETE | `/api/v1/sboms/{id}` | **None** ⚠️ | — | — | — | **GAP: no auth or ownership check** |

---

## Components

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| GET | `/api/v1/components` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/components/distinct` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/components/purl-types` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/components/versions` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/components/{id}` | None | — | — | SQL (service layer) | |

---

## Licenses

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| GET | `/api/v1/licenses` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/licenses/{id}/components` | None | — | — | SQL (service layer) | |

---

## Artifacts

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| GET | `/api/v1/artifacts` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/artifacts/{id}` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/artifacts/{id}/sboms` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/artifacts/{id}/changelog` | None | — | — | SQL (service layer) | |
| GET | `/api/v1/artifacts/{id}/license-summary` | None | — | — | SQL (service layer) | |
| DELETE | `/api/v1/artifacts/{id}` | **None** ⚠️ | — | — | — | **GAP: no auth or ownership check** |

---

## Registries

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| POST | `/api/v1/registries/{id}/webhook` | Secret | — | — | — | Validated by webhook bearer secret, not user identity |
| POST | `/api/v1/registries/test-connection` | Handler 401 | admin | — | — | |
| GET | `/api/v1/registries` | Handler 401 | any | Owner+admin filter (service) | SQL (service layer) | |
| POST | `/api/v1/registries` | Handler 401 | any | — | — | Any authenticated user can create |
| GET | `/api/v1/registries/{id}` | Handler 401 | any | Handler: private→404 for non-owner | — | |
| PATCH | `/api/v1/registries/{id}` | Handler 401 | any | Handler: owner \| admin | — | |
| DELETE | `/api/v1/registries/{id}` | Handler 401 | any | Handler: owner \| admin | — | |
| POST | `/api/v1/registries/{id}/scan` | Handler 401 | any | Handler: owner \| admin | — | |
| POST | `/api/v1/registries/{id}/webhook-secret` | Handler 401 | any | Handler: owner \| admin | — | |

---

## Stats

| Method | Path | Auth Required | Required Role | Ownership Check | Visibility Filter | Notes |
|--------|------|---------------|---------------|-----------------|-------------------|-------|
| GET | `/api/v1/stats` | None | — | — | SQL (service layer) | |

---

## Gaps Requiring Handler-Level Enforcement

The following endpoints need handler-level auth added. They currently have no gate and rely entirely on the service/SQL layer (or nothing at all).

### Critical — unauthenticated mutation

| # | Endpoint | Issue | Recommended Fix |
|---|----------|-------|-----------------|
| 1 | `POST /api/v1/sboms` | Anyone (unauthenticated) can ingest SBOMs | Require auth; require `member` or `admin` role |
| 2 | `DELETE /api/v1/sboms/{id}` | Anyone can delete any SBOM | Require auth; require ownership of the parent artifact or `admin` role |
| 3 | `DELETE /api/v1/artifacts/{id}` | Anyone can delete any artifact | Require auth; require ownership or `admin` role |

### Design decisions to document

| # | Endpoint | Observation |
|---|----------|-------------|
| 4 | All read endpoints (SBOMs, components, licenses, artifacts, stats) | Intentionally public for unauthenticated browse. Visibility filtering is SQL-layer only. This is by design but should be documented — there is no handler gate to fall back on if the SQL filter has a bug. |
| 5 | `POST /api/v1/registries` | Any authenticated user can create registries (no role gate). Intentional? Worth making explicit. |
| 6 | `GET /api/v1/registries/{id}` | Private registries return 404 (not 403) for non-owners. This obscures existence — intentional security-by-obscurity, acceptable for most cases. |
