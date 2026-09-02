package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/authz"
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
// deriveFrontendURL follows the host the browser actually used rather than the
// one in configuration. Handlers that only need headers, path, or body must
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
func OptionalAuthenticate(authSvc service.AuthService) func(http.Handler) http.Handler {
	if authSvc == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				user service.AuthUser
				err  error
			)

			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				user, err = authSvc.ValidateAPIKey(r.Context(), token)
			} else if c, cerr := r.Cookie("ocidex_session"); cerr == nil {
				user, err = authSvc.ValidateSession(r.Context(), c.Value)
			} else {
				// No credentials — continue without user context.
				next.ServeHTTP(w, r)
				return
			}

			if err != nil {
				// Invalid credentials — continue without user context.
				next.ServeHTTP(w, r)
				return
			}

			// Namespace grants are resolved here, once, and attached to the
			// principal for the life of the request (ocidex-y0hg.5). Once,
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
			grants, gerr := authSvc.LoadGrants(r.Context(), user.ID)
			if gerr != nil {
				slog.WarnContext(r.Context(), "loading namespace grants", "error", gerr)
			}
			user.Grants = grants

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser{}, user)))
		})
	}
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
// 403s every caller without the admin role.
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
		next(ctx)
	}
}

// RequireCapability returns a huma middleware that admits only a caller holding
// capability c in the namespace resolve derives from the request.
//
// It replaces RequireRegistryOwner, RequireSBOMOwner and RequireArtifactOwner
// (ocidex-y0hg.5), which differed from each other only in how they found the
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
//   - resolve yields an invalid UUID: the resource hangs from no namespace.
//     Legacy uploaded rows are like this — sbom.namespace_id is still nullable
//     and the visibility functions treat the NULL arm as public — so this
//     admits any member or admin, exactly as the ownership middlewares did.
//     That arm dies with the nullable column (ocidex-0gp.3), not before: making
//     it a 403 now would strand every pre-namespace upload behind admin.
//   - Otherwise: authz.Allow through can(), so an admin passes regardless of
//     membership and a member without c gets 403.
func RequireCapability(api huma.API, c authz.Capability,
	resolve func(huma.Context) (pgtype.UUID, error),
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
		if !namespaceID.Valid {
			if user.Role != roleAdmin && user.Role != roleMember {
				_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
				return
			}
			next(ctx)
			return
		}
		if !can(user, uuidToStr(namespaceID), c) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
			return
		}
		next(ctx)
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
		// reproduce with. RouteContext is only populated once next has routed,
		// which is why this reads it after ServeHTTP.
		route := r.URL.Path
		if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePattern() != "" {
			route = rctx.RoutePattern()
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
