package api

import (
	"net/http"
	"strings"
)

// The /api/v1 naming rule (ocidex-nps9.7, docs/API_VERSIONING.md): field
// names, query parameter names and sort keys are camelCase. Enum values that
// name a state rather than a field (egress_denied, verification_failed) are not
// field names and keep their spelling.

// snakeToCamel spells a snake_case name in camelCase: subject_version → subjectVersion.
func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// LegacyQueryNames accepts the snake_case query parameter names and sort keys
// /api/v1 used before 1.0 (ocidex-nps9.34), rewriting them to camelCase before
// the request is parsed. It exists for one release so an ocidex-cli older than
// the server, which CI images pin, keeps sending working ingest parameters
// (subject_name, build_date, …) instead of having them silently ignored.
// Remove it in the release after 1.0 (ocidex-6hfs).
//
// The rewrite is mechanical, so it needs no table: every /api/v1 parameter name
// is camelCase, and no camelCase name contains an underscore. A camelCase name
// already present wins over its legacy spelling.
func LegacyQueryNames(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "" || !strings.Contains(r.URL.RawQuery, "_") || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		q := r.URL.Query()
		changed := false
		for key, vals := range q {
			if !strings.Contains(key, "_") {
				continue
			}
			camel := snakeToCamel(key)
			if _, ok := q[camel]; !ok {
				q[camel] = vals
			}
			delete(q, key)
			changed = true
		}
		if sort := q.Get("sort"); strings.Contains(sort, "_") {
			q.Set("sort", snakeToCamel(sort))
			changed = true
		}
		if changed {
			r.URL.RawQuery = q.Encode()
		}
		next.ServeHTTP(w, r)
	})
}
