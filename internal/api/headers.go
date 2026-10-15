package api

import (
	"net/http"
	"strings"
)

// noStorePrefixes are the paths whose responses carry a session, a credential
// or the caller's own identity: sign-in and its redirects, API keys, and
// /users/me. No cache, shared or private, may keep them.
var noStorePrefixes = []string{"/auth/", "/api/v1/auth/", "/api/v1/users/me"}

// SecurityHeaders sets the API's response hardening headers (ocidex-mqav.7):
// nosniff on everything, so a JSON body is never sniffed into something a
// browser would render, and Cache-Control: no-store on noStorePrefixes. The
// web tier's CSP and friends live in web/nginx.conf; the API serves no HTML a
// CSP would govern.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		for _, p := range noStorePrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				w.Header().Set("Cache-Control", "no-store")
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}
