package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/pfenerty/ocidex/internal/service"
)

// publicPaths bypass Authenticate.
var publicPaths = map[string]bool{
	"/health":        true,
	"/ready":         true,
	"/auth/login":    true,
	"/auth/callback": true,
}

type ctxKeyUser struct{}

// Authenticate validates session cookies and Bearer API keys.
// Public paths are passed through without auth. If authSvc is nil, all requests pass through (useful for tests).
func Authenticate(authSvc service.AuthService) func(http.Handler) http.Handler {
	if authSvc == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if publicPaths[r.URL.Path] ||
				(strings.HasPrefix(r.URL.Path, "/api/v1/registries/") && strings.HasSuffix(r.URL.Path, "/webhook")) {
				next.ServeHTTP(w, r)
				return
			}

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
				err = errUnauthorized
			}

			if err != nil {
				writeUnauthorized(w)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser{}, user)))
		})
	}
}

var errUnauthorized = fmt.Errorf("unauthorized")

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

// RequireRole returns middleware that enforces one of the given roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok || !allowed[user.Role] {
				writeForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
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

// RequireSBOMOwner returns a huma middleware that requires auth + ownership of
// the SBOM's linked registry OR admin role. If the SBOM has no registry
// association, any authenticated member|admin is allowed. When sbomSvc or
// regSvc is nil the ownership check is skipped but auth is still enforced.
func RequireSBOMOwner(api huma.API, sbomSvc service.SBOMService, regSvc service.RegistryService) func(huma.Context, func(huma.Context)) {
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
		if sbomSvc == nil || regSvc == nil {
			next(ctx)
			return
		}
		id, err := parseUUID(ctx.Param("id"))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "sbom not found")
			return
		}
		registryID, err := sbomSvc.GetSBOMRegistryID(ctx.Context(), id)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusNotFound, "sbom not found")
			return
		}
		if !registryID.Valid {
			// No registry association — any member|admin may delete.
			next(ctx)
			return
		}
		reg, err := regSvc.Get(ctx.Context(), uuidToStr(registryID))
		if err != nil || !canManageRegistry(user, reg) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "forbidden")
			return
		}
		next(ctx)
	}
}

// RequireArtifactOwner returns a huma middleware that requires auth + ownership
// of any registry linked to the artifact OR admin role. If the artifact has no
// registry association, any authenticated member|admin is allowed. When sbomSvc
// or regSvc is nil the ownership check is skipped but auth is still enforced.
func RequireArtifactOwner(api huma.API, sbomSvc service.SBOMService, regSvc service.RegistryService) func(huma.Context, func(huma.Context)) {
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
		if sbomSvc == nil || regSvc == nil {
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
			// No registry owner linked — any member|admin may delete.
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

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "status": 401, "title": "Unauthorized"}); err != nil {
		slog.Error("encoding error response", "err", err)
	}
}

func writeForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "status": 403, "title": "Forbidden"}); err != nil {
		slog.Error("encoding error response", "err", err)
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
