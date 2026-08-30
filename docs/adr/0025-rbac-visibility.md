# ADR 0025: RBAC and Visibility Model

**Status:** Superseded by [ADR-046](0046-namespace-membership-rbac.md)  
**Date:** 2026-06-06

> **Superseded.** Kept unedited as the record of why the simple model was chosen, and
> because its Consequences section predicted its own replacement. Two changes have since
> invalidated it. [ADR-039](0039-namespace-and-source-model.md) moved the authorization
> anchor from registry to namespace, so `RequireRegistryOwner` and the registry `public`
> boolean described below no longer exist. [ADR-046](0046-namespace-membership-rbac.md)
> then replaced single ownership with per-namespace membership and a capability matrix,
> and replaced the `read` / `read-write` API key scope with a capability ceiling
> intersected against the holder's live roles. Read ADR-046 for the model in force.

## Context

OCIDex stores registry metadata on behalf of multiple users. As the feature set grew, three overlapping concerns emerged:

1. **Registry ownership** — who can modify a registry's configuration and trigger scans.
2. **Artifact/SBOM visibility** — whether unauthenticated or low-privilege callers can read data for a given registry.
3. **API key scopes** — programmatic callers need read-only vs. read-write distinctions.

The project chose a simple ownership model over a full RBAC system; complexity would be added only if multi-tenancy requirements grew beyond single-owner registries.

## Decision

### Roles

| Role | Who | Can read public data | Can write | Can admin |
|------|-----|---------------------|-----------|-----------|
| Unauthenticated | No session/key | Public registries only | No | No |
| Member (session) | OAuth login, no ownership | Public registries + own data | Own resources | No |
| Registry Owner | Creator of the registry | All data for that registry | Yes | Registry config |
| Admin | Platform-level flag | Everything | Everything | Everything |

### Visibility

Registries have a `public` boolean. When `public = true`, unauthenticated callers may read artifacts and SBOMs associated with that registry. When `public = false`, only the owner and admins may read.

The check is enforced in `internal/api/middleware.go` (`RequireRegistryOwner`) and in `internal/service/registry.go` (visibility checks before returning data).

### API Key Scopes

API keys carry a `scope` field: `read` or `write`. Handlers check `isWriteAllowed(user)` (defined in `internal/api/auth.go`) before any mutating operation. Read-only keys receive HTTP 403 on POST/PUT/PATCH/DELETE endpoints.

Session-authenticated users (OAuth) are implicitly read-write for their own resources.

### Auth Flow

1. Every request passes through `OptionalAuthenticate` middleware (`internal/api/middleware.go`).
2. The middleware resolves the caller identity from either a `Bearer` API key or a session cookie and attaches a `User` struct to the request context.
3. Handlers call `UserFromContext(ctx)` to retrieve the identity; absence means unauthenticated.
4. Ownership checks use `RequireRegistryOwner`, which compares `user.ID` against the registry's `owner_id`.

## Consequences

- Simple to reason about: one owner per registry, one flag for public/private.
- No group/team model — all team access is handled outside OCIDex (shared API keys).
- Upgrading to a full RBAC model later would require a new `roles` table and migration; the interface points (`UserFromContext`, `isWriteAllowed`, `RequireRegistryOwner`) are the extension seams.

## Key Files

- `internal/api/auth.go` — `isWriteAllowed`, `UserFromContext`, session/key resolution
- `internal/api/middleware.go` — `OptionalAuthenticate`, `RequireRegistryOwner`
- `internal/service/auth.go` — session and API key service logic
- `docs/AUTH_MATRIX.md` — endpoint-level auth matrix
