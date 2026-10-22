package health_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/health"
)

func TestMetricsRoute(t *testing.T) {
	is := is.New(t)
	get := func(h http.Handler, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}

	plain := health.New(":0", nil, nil, nil).Handler()
	is.Equal(get(plain, "/healthz"), http.StatusOK)
	is.Equal(get(plain, "/metrics"), http.StatusNotFound) // no handler, no route

	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	withMetrics := health.New(":0", nil, nil, nil).WithMetrics(metricsHandler).Handler()
	is.Equal(get(withMetrics, "/metrics"), http.StatusTeapot)
	is.Equal(get(withMetrics, "/readyz"), http.StatusOK)
}
