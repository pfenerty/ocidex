package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel/metric"

	"github.com/pfenerty/ocidex/internal/metrics"
)

// TestHandlerServesScrapedNames checks the names Prometheus sees, which the
// exporter derives from the instrument names (ADR-0054 M3, M5).
func TestHandlerServesScrapedNames(t *testing.T) {
	is := is.New(t)
	p, err := metrics.New(t.Context(), "ocidex-test")
	is.NoErr(err)
	t.Cleanup(func() { _ = p.Shutdown(t.Context()) })

	m := metrics.Meter(p)
	jobs, err := m.Int64Counter("ocidex.jobs.processed", metric.WithUnit("{job}"))
	is.NoErr(err)
	jobs.Add(t.Context(), 1)
	dur, err := m.Float64Histogram("http.server.request.duration", metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metrics.DurationBuckets...))
	is.NoErr(err)
	dur.Record(t.Context(), 0.2)

	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	is.Equal(rec.Code, http.StatusOK)
	body, _ := io.ReadAll(rec.Body)
	text := string(body)

	for _, want := range []string{
		"ocidex_jobs_processed_total ",
		`http_server_request_duration_seconds_bucket{le="5"}`,
		"http_server_request_duration_seconds_count ",
		"go_goroutine_count",
		"process_cpu_seconds_total",
		`target_info{`,
		`service_name="ocidex-test"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("scrape is missing %q", want)
		}
	}
	if strings.Contains(text, "otel_scope_") {
		t.Error("scrape carries otel_scope_* labels; WithoutScopeInfo should drop them")
	}
}

func TestServerServesMetricsPath(t *testing.T) {
	is := is.New(t)
	p, err := metrics.New(t.Context(), "ocidex-test")
	is.NoErr(err)
	t.Cleanup(func() { _ = p.Shutdown(t.Context()) })

	srv := httptest.NewServer(metrics.NewServer("", p.Handler(), nil).Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/metrics")
	is.NoErr(err)
	_ = resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusOK)

	resp, err = http.Get(srv.URL + "/")
	is.NoErr(err)
	_ = resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusNotFound) // only /metrics is served
}
