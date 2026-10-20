package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/pfenerty/ocidex/internal/api"
)

// requestPoints reads http.server.request.duration back from reader and
// returns its data points keyed by "METHOD route".
func requestPoints(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.HistogramDataPoint[float64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]metricdata.HistogramDataPoint[float64]{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			if m.Unit != "s" {
				t.Fatalf("unit = %q, want s", m.Unit)
			}
			for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
				route, _ := dp.Attributes.Value(attribute.Key("http.route"))
				method, _ := dp.Attributes.Value(attribute.Key("http.request.method"))
				out[method.AsString()+" "+route.AsString()] = dp
			}
		}
	}
	return out
}

func TestRequestMetrics(t *testing.T) {
	is := is.New(t)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{}).WithMeterProvider(mp)
	router := api.NewRouter(h, "*", "", "")

	for _, path := range []string{
		"/api/v1/sboms/00000000-0000-0000-0000-000000000001",
		"/api/v1/sboms/00000000-0000-0000-0000-000000000002",
		"/no/such/path/1",
		"/no/such/path/2",
	} {
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("BREW", "/health", nil))

	got := requestPoints(t, reader)

	sbom, ok := got["GET /api/v1/sboms/{id}"]
	is.True(ok) // matched requests carry the route pattern, not the path
	is.Equal(sbom.Count, uint64(2))
	_, hasStatus := sbom.Attributes.Value("http.response.status_code")
	is.True(hasStatus)

	unmatched, ok := got["GET unmatched"]
	is.True(ok) // unknown paths collapse to one series
	is.Equal(unmatched.Count, uint64(2))
	status, _ := unmatched.Attributes.Value("http.response.status_code")
	is.Equal(status.AsInt64(), int64(http.StatusNotFound))

	_, ok = got["_OTHER unmatched"]
	is.True(ok) // a non-standard method is recorded as _OTHER
	is.Equal(len(got), 3)
}
