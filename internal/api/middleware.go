package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/pfenerty/ocidex/internal/service"
)

const (
	scopeRead      = "read"
	scopeReadWrite = "read-write"
)

// isWriteAllowed reports whether the user may perform state-mutating operations.
// Session-authenticated users (empty APIKeyScope) always have write access.
func isWriteAllowed(user service.AuthUser) bool {
	return user.APIKeyScope == "" || user.APIKeyScope == scopeReadWrite
}

type ctxKeyUser struct{}

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

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser{}, user)))
		})
	}
}

// UserFromContext retrieves the authenticated user from a request context.
func UserFromContext(ctx context.Context) (service.AuthUser, bool) {
	u, ok := ctx.Value(ctxKeyUser{}).(service.AuthUser)
	return u, ok
}

// RequireRegistryOwner returns a huma middleware that loads the registry from
// the {id} path param and rejects with 403 unless the caller is the owner or
// an admin. Pass a nil svc to skip the check (useful in tests that don't wire
// a registry service).
func RequireRegistryOwner(api huma.API, svc service.RegistryService) func(huma.Context, func(huma.Context)) {
	if svc == nil {
		return func(ctx huma.Context, next func(huma.Context)) { next(ctx) }
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		user, ok := UserFromContext(ctx.Context())
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "not authenticated")
			return
		}
		reg, err := svc.Get(ctx.Context(), ctx.Param("id"))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "registry not found")
			return
		}
		if !canManageRegistry(user, reg) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
			return
		}
		next(ctx)
	}
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

// RequireWrite returns a huma middleware that 403s a caller presenting a
// read-scoped API key. It checks the key scope only and is deliberately
// orthogonal to the auth-class middlewares (RequireAuthenticated, RequireMember,
// RequireAdmin, Require*Owner): a state-mutating operation declares one of those
// plus this one, and authentication is enforced by the auth-class middleware
// listed first.
func RequireWrite(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if user, ok := UserFromContext(ctx.Context()); ok && !isWriteAllowed(user) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "read-only API key cannot perform write operations")
			return
		}
		next(ctx)
	}
}

// RequireSBOMOwner returns a huma middleware that requires auth + ownership of
// the SBOM's namespace OR admin role. If the SBOM has no namespace association,
// any authenticated member|admin is allowed. When sbomSvc or nsSvc is nil the
// ownership check is skipped but auth is still enforced.
func RequireSBOMOwner(api huma.API, sbomSvc service.SBOMService, nsSvc service.NamespaceService) func(huma.Context, func(huma.Context)) {
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
		if sbomSvc == nil || nsSvc == nil {
			next(ctx)
			return
		}
		id, err := parseUUID(ctx.Param("id"))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "sbom not found")
			return
		}
		namespaceID, err := sbomSvc.GetSBOMNamespaceID(ctx.Context(), id)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "sbom not found")
			return
		}
		if !namespaceID.Valid {
			next(ctx)
			return
		}
		ns, err := nsSvc.Get(ctx.Context(), uuidToStr(namespaceID))
		if err != nil || !canManageNamespace(user, ns) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
			return
		}
		next(ctx)
	}
}

// RequireArtifactOwner returns a huma middleware that requires auth + ownership
// of any namespace linked to the artifact OR admin role. If the artifact has no
// namespace association, any authenticated member|admin is allowed. When sbomSvc
// or nsSvc is nil the ownership check is skipped but auth is still enforced.
func RequireArtifactOwner(api huma.API, sbomSvc service.SBOMService, nsSvc service.NamespaceService) func(huma.Context, func(huma.Context)) {
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
		if sbomSvc == nil || nsSvc == nil {
			next(ctx)
			return
		}
		id, err := parseUUID(ctx.Param("id"))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "artifact not found")
			return
		}
		ownerID, err := sbomSvc.GetArtifactOwnerID(ctx.Context(), id)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "artifact not found")
			return
		}
		if !ownerID.Valid {
			next(ctx)
			return
		}
		if user.Role == roleAdmin {
			next(ctx)
			return
		}
		if !user.ID.Valid || uuidToStr(ownerID) != uuidToStr(user.ID) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
			return
		}
		next(ctx)
	}
}

// SlogLogger returns middleware that logs each request using slog.
func SlogLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		slog.InfoContext(r.Context(), "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}
