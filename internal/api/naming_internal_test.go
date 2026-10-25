package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

// An ocidex-cli older than the server sends the pre-1.0 snake_case names
// (ocidex-nps9.34); they must reach the handler under the camelCase ones.
func TestLegacyQueryNames(t *testing.T) {
	is := is.New(t)
	var got string
	h := LegacyQueryNames(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.URL.RawQuery }))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost,
		"/api/v1/sboms?subject_name=ocidex&build_date=2026-10-24&source=s1", nil))
	is.Equal(got, "buildDate=2026-10-24&source=s1&subjectName=ocidex")

	// The camelCase spelling wins when both are sent.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
		"/api/v1/clusters/x/workloads?k8s_namespace=old&k8sNamespace=new&sort=vuln_count", nil))
	is.Equal(got, "k8sNamespace=new&sort=vulnCount")

	// Nothing to do: the query is passed through untouched.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/vulns?sort=cvssScore&q=a%20b", nil))
	is.Equal(got, "sort=cvssScore&q=a%20b")

	// Not an API path: untouched.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/docs?some_thing=1", nil))
	is.Equal(got, "some_thing=1")
}
