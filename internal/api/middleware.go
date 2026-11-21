package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/service"
)

// isWriteAllowed reports whether the credential the request arrived on may
// perform state-mutating operations at all.
//
// It asks one question — does this key carry any mutating capability — and
// deliberately not "which one". The per-operation capability declared alongside
// Write is what narrows an individual endpoint; this stays the coarse gate it
// has always been, so the ~40 operations that declare Write keep meaning
// exactly what they meant under the read / read-write pair.
func isWriteAllowed(user service.AuthUser) bool {
	return user.KeyAllowsAnyWrite()
}

type ctxKeyUser struct{}

type ctxKeyRequest struct{}

// WithRequest stashes the *http.Request on its own context.
//
// It exists for the handful of huma handlers that need something huma's typed
// input cannot carry: the Host and TLS state of the connection, which is how
// deriveFrontendURL can follow the host the browser actually used (outside
// production, and only to an allowed origin) rather than the one in
// configuration. Handlers that only need headers, path, or body must
// keep declaring them on their input struct.
func WithRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequest{}, r)))
	})
}

// requestFromContext retrieves the request stashed by WithRequest.
func requestFromContext(ctx context.Context) (*http.Request, bool) {
	r, ok := ctx.Value(ctxKeyRequest{}).(*http.Request)
	return r, ok
}

// OptionalAuthenticate attaches the user to the context if a valid session or
// API key is present, but allows unauthenticated requests through (user will
// be absent from context). Use this for browse endpoints that should be
// accessible to the public but can show more data to authenticated users.
func OptionalAuthenticate(authSvc Authenticator) func(http.Handler) http.Handler {
	if authSvc == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				user service.AuthUser
				err  error
			)

			switch method, secret := presentedCredential(r); method {
			case authMethodBearer:
				user, err = authSvc.ValidateAPIKey(r.Context(), secret)
			case authMethodCookie:
				user, err = authSvc.ValidateSession(r.Context(), secret)
			case authMethodNone:
				// No credentials — continue without user context.
				next.ServeHTTP(w, r)
				return
			}

			if errors.Is(err, service.ErrNotFound) {
				// Invalid credentials — continue without user context.
				next.ServeHTTP(w, r)
				return
			}
			if err != nil {
				// The credential could not be checked (a database fault). Demoting
				// the caller to anonymous would answer 401 on authenticated routes
				// and send operators chasing credentials during an outage.
				slog.ErrorContext(r.Context(), "validating credentials", "error", err)
				writeCredentialCheckUnavailable(w)
				return
			}

			if note := notePushFromContext(r.Context()); note != nil {
				note.authenticated = true
			}

			// Namespace grants are resolved here, once, and attached to the
			// principal for the life of the request. Once,
			// because a capability check happens in middleware and again in the
			// handler and a per-check query would multiply for free; here,
			// because the alternative — writing the grant set onto the session
			// or API-key row — would mean a role change only took effect at the
			// next login, which the epic explicitly rules out.
			//
			// A failure to load grants is not a failure to authenticate: the
			// caller continues with no grants, which denies every capability
			// check but still answers public-class routes. Failing the whole
			// request would take the browse surface down with the membership
			// table.
			// A cluster agent credential is refused everywhere
			// but its own inventory push. Checked here, before any route runs,
			// so a route added later cannot forget to exclude it; and refused
			// rather than demoted to anonymous, which would still let it read
			// public data.
			if user.APIKeyClusterID != "" && !clusterCredentialRoute(r, user.APIKeyClusterID) {
				if note := notePushFromContext(r.Context()); note != nil {
					note.boundClusterID = user.APIKeyClusterID // authenticated is already set
				}
				writeClusterCredentialForbidden(w)
				return
			}

			grants, gerr := authSvc.LoadGrants(r.Context(), user.ID)
			if gerr != nil {
				slog.WarnContext(r.Context(), "loading namespace grants", "error", gerr)
			}
			user.Grants = grants

			ctx := context.WithValue(r.Context(), ctxKeyUser{}, user)
			ctx = event.WithActor(ctx, actorFor(user))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// actorFor is the audit actor for an authenticated caller: the user, and the
// key when the request came in on one.
func actorFor(user service.AuthUser) event.Actor {
	return event.Actor{Kind: event.ActorUser, ID: user.ID, APIKeyID: user.APIKeyID}
}

// clusterCredentialRoute reports whether r is the one request a credential
// bound to clusterID may make: pushing that cluster's inventory.
func clusterCredentialRoute(r *http.Request, clusterID string) bool {
	return r.Method == http.MethodPost &&
		strings.EqualFold(r.URL.Path, "/api/v1/clusters/"+clusterID+"/inventory")
}

func writeCredentialCheckUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"title":"Service Unavailable","status":503,"detail":"credentials could not be checked; try again"}`))
}

func writeClusterCredentialForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"title":"Forbidden","status":403,"detail":"a cluster agent credential may only push its own cluster's inventory"}`))
}

// UserFromContext retrieves the authenticated user from a request context.
func UserFromContext(ctx context.Context) (service.AuthUser, bool) {
	u, ok := ctx.Value(ctxKeyUser{}).(service.AuthUser)
	return u, ok
}

// RequireMember returns a huma middleware that 401s unauthenticated callers and
// 403s callers without member or admin role.
func RequireMember(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user, ok := UserFromContext(ctx.Context())
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "not authenticated")
			return
		}
		if user.Role != roleAdmin && user.Role != roleMember {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
			return
		}
		next(ctx)
	}
}

// RequireAuthenticated returns a huma middleware that 401s unauthenticated
// callers and imposes no role constraint. It exists so that "any authenticated
// principal" is a declared auth class on the operation rather than an implicit
// one buried in the handler body.
func RequireAuthenticated(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if _, ok := UserFromContext(ctx.Context()); !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "not authenticated")
			return
		}
		next(ctx)
	}
}

// RequireAdmin returns a huma middleware that 401s unauthenticated callers and
// 403s every caller without the admin role. An admin presenting an API key also
// needs the key to carry authz.CapInstallationAdmin: the admin role is the owner's, and a
// key is a ceiling over what its owner may do.
func RequireAdmin(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user, ok := UserFromContext(ctx.Context())
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "not authenticated")
			return
		}
		if user.Role != roleAdmin {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "admin only")
			return
		}
		if !user.KeyAllows(authz.CapInstallationAdmin) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "API key lacks the installation_admin capability")
			return
		}
		next(ctx)
	}
}

// RequireCapability returns a huma middleware that admits only a caller holding
// capability c in the namespace resolve derives from the request.
//
// It replaces RequireRegistryOwner, RequireSBOMOwner and RequireArtifactOwner
// , which differed from each other only in how they found the
// namespace and then asked the same hard-coded "are you the owner" question.
// resolve is those bodies lifted out: everything above it is one rule, declared
// once, and an operation names the capability it needs rather than a role that
// happens to have it.
//
// The answers:
//
//   - No credentials: 401. A capability is a property of a principal and there
//     is no anonymous membership.
//   - resolve fails: 404. resolve loads the target resource, so its failure is
//     the resource not existing (or not being visible), and a caller who may
//     not act on a thing must not learn it exists from the status code.
//   - Otherwise: authz.Allow through can(), so an admin passes regardless of
//     membership and a member without c gets 403. A resolver that yields an
//     invalid UUID — a resource hanging from no namespace — falls into the same
//     rule, where no membership can cover it and only an admin passes. No live
//     row is like that: sbom.namespace_id has been NOT NULL since 00054, and the
//     registry, artifact and namespace resolvers read NOT NULL columns or
//     inner joins.
func RequireCapability(api huma.API, c authz.Capability,
	resolve func(huma.Context) (string, error),
) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user, ok := UserFromContext(ctx.Context())
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "not authenticated")
			return
		}
		namespaceID, err := resolve(ctx)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "not found")
			return
		}
		if !can(user, namespaceID, c) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
			return
		}
		next(ctx)
	}
}

// RequireCapabilityInAny is RequireCapability for a resource that hangs from
// several namespaces at once (a shared artifact): it admits a caller holding c
// in at least one of the namespaces resolve returns. Admission says only that
// the caller may act somewhere on the resource; the handler must still confine
// the action to the namespaces where the caller holds c, never to all of them.
//
// The answers match RequireCapability's: 401 without credentials, 404 when
// resolve fails, 403 when no namespace grants c. A resource hanging from no
// namespace is admin-only.
func RequireCapabilityInAny(api huma.API, c authz.Capability,
	resolve func(huma.Context) ([]string, error),
) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		user, ok := UserFromContext(ctx.Context())
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "not authenticated")
			return
		}
		namespaceIDs, err := resolve(ctx)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "not found")
			return
		}
		if len(namespaceIDs) == 0 {
			namespaceIDs = []string{""}
		}
		for _, ns := range namespaceIDs {
			if can(user, ns, c) {
				next(ctx)
				return
			}
		}
		_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
	}
}

// RequireWrite returns a huma middleware that 403s a caller presenting an API
// key that carries no mutating capability. It checks the key's ceiling only and
// is deliberately
// orthogonal to the auth-class middlewares (RequireAuthenticated, RequireMember,
// RequireAdmin, RequireCapability): a state-mutating operation declares one of
// those plus this one, and authentication is enforced by the auth-class
// middleware listed first.
func RequireWrite(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if user, ok := UserFromContext(ctx.Context()); ok && !isWriteAllowed(user) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "read-only API key cannot perform write operations")
			return
		}
		next(ctx)
	}
}

// slowRequestThreshold is the latency past which a request is logged at Warn
// rather than Info.
//
// It is well under router.go's 30s middleware.Timeout on purpose: by the time a
// request times out a user has already seen the failure, so the only useful
// signal is the one that fires while an endpoint is merely getting slow. 5s is
// where the slowest healthy endpoint sits today (/artifacts/{id}/contains, at
// ~4.2s against the widest artifact in the corpus), which makes a crossing here
// a genuine change rather than routine noise.
const slowRequestThreshold = 5 * time.Second

// SlogLogger returns middleware that logs each request using slog.
func SlogLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		elapsed := time.Since(start)

		// route is the chi pattern, not r.URL.Path: the path carries inline
		// UUIDs, so every request to an artifact endpoint is its own unique
		// string and no aggregation over "how slow is this endpoint" is
		// possible. Both are logged — the pattern to group by, the path to
		// reproduce with.
		route, ok := routePattern(r)
		if !ok {
			route = r.URL.Path
		}

		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"route", route,
			"status", ww.Status(),
			"duration_ms", elapsed.Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		}

		if elapsed >= slowRequestThreshold {
			slog.WarnContext(r.Context(), "slow request", attrs...)
			return
		}

		slog.InfoContext(r.Context(), "request", attrs...)
	})
}
