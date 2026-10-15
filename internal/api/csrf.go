package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
)

// authMethod records which credential OptionalAuthenticate accepted. Only a
// cookie is an ambient credential — one the browser attaches to a request some
// other site initiated — so it is the only one CrossOriginGuard polices.
type authMethod int

const (
	authMethodNone authMethod = iota
	authMethodBearer
	authMethodCookie
)

type ctxKeyAuthMethod struct{}

// authMethodFromContext reports how the request's principal authenticated, or
// authMethodNone when it did not.
func authMethodFromContext(ctx context.Context) authMethod {
	m, _ := ctx.Value(ctxKeyAuthMethod{}).(authMethod)
	return m
}

// CrossOriginGuard rejects state-changing requests that authenticated by
// session cookie unless they demonstrably came from a trusted origin — the
// OWASP "verify origin with standard headers" defence (ocidex-mqav.1).
//
// huma only enforces Content-Type when an operation has a body, so without
// this a body-less POST (scan a registry, rotate a webhook secret, retry every
// failed job) can be forged by a plain HTML form on any site the victim
// visits.
//
// The trusted set is allowedOrigins (the parsed CORS origins) plus the API's
// own origin: apiBaseURL when set, otherwise the scheme and host the request
// arrived on. A "*" in allowedOrigins admits any origin, because a wildcard
// CORS policy with credentials already lets every site read authenticated
// responses and refusing its writes would protect nothing.
//
// The Origin header is checked first and Referer's origin second; a request
// carrying neither is refused, since every browser sends Origin on a
// cross-origin POST and a same-origin fetch sends it too. Bearer-authenticated
// and anonymous requests pass untouched: an API key is not ambient.
func CrossOriginGuard(allowedOrigins []string, apiBaseURL string) func(http.Handler) http.Handler {
	trusted := make(map[string]bool, len(allowedOrigins)+1)
	wildcard := false
	for _, o := range allowedOrigins {
		if o == "*" {
			wildcard = true
			continue
		}
		if n := normalizeOrigin(o); n != "" {
			trusted[n] = true
		}
	}
	self := normalizeOrigin(apiBaseURL)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isStateChanging(r.Method) || authMethodFromContext(r.Context()) != authMethodCookie {
				next.ServeHTTP(w, r)
				return
			}

			origin := requestOrigin(r)
			if origin != "" && (wildcard || trusted[origin] || origin == selfOrigin(r, self)) {
				next.ServeHTTP(w, r)
				return
			}

			// The router has not matched yet, so the route pattern is whatever
			// chi can resolve up front; the path is logged alongside for the
			// cases it cannot.
			route := r.URL.Path
			if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.Routes != nil {
				if tctx := chi.NewRouteContext(); rctx.Routes.Match(tctx, r.Method, r.URL.Path) {
					route = tctx.RoutePattern()
				}
			}
			slog.WarnContext(r.Context(), "cross-origin request rejected",
				"method", r.Method, "route", route, "origin", origin)
			writeProblem(w, http.StatusForbidden, "cross-origin request rejected")
		})
	}
}

// isStateChanging reports whether method may mutate state.
func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// requestOrigin returns the normalized origin the request claims to come from:
// the Origin header, or failing that the origin of the Referer.
func requestOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		return normalizeOrigin(o)
	}
	return normalizeOrigin(r.Header.Get("Referer"))
}

// selfOrigin is the API's own origin: the configured one when there is one,
// otherwise the scheme and host the request arrived on.
func selfOrigin(r *http.Request, configured string) string {
	if configured != "" {
		return configured
	}
	scheme := schemeHTTP
	if r.TLS != nil {
		scheme = schemeHTTPS
	}
	return normalizeOrigin(scheme + "://" + r.Host)
}

// normalizeOrigin reduces a URL to its lowercased scheme://host[:port], or ""
// when raw is not an absolute http(s) URL. The opaque origin "null" is "".
func normalizeOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != schemeHTTP && scheme != schemeHTTPS {
		return ""
	}
	return scheme + "://" + strings.ToLower(u.Host)
}

// writeProblem writes an RFC 7807 problem document from plain chi middleware,
// where huma's API is not to hand, in the same shape huma.WriteErr produces.
func writeProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(huma.ErrorModel{
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	})
}
