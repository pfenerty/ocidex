package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matryer/is"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/tracing"
)

const secret = "s3cr3t-token-value"

func TestRequestSpans(t *testing.T) {
	is := is.New(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(tracing.RedactExporter(exp)))
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{}).WithTracerProvider(tp)
	router := api.NewRouter(h, "*", "", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/00000000-0000-0000-0000-000000000001?token="+secret, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Cookie", "ocidex_session="+secret)
	req.Header.Set("Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	router.ServeHTTP(httptest.NewRecorder(), req)
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ready", nil))

	spans := exp.GetSpans()
	is.Equal(len(spans), 1) // probes are not traced
	s := spans[0]
	is.Equal(s.Name, "GET /api/v1/sboms/{id}")
	is.Equal(s.Parent.TraceID().String(), "0af7651916cd43dd8448eb211c80319c") // continues the caller's trace
	var route string
	for _, kv := range s.Attributes {
		if kv.Key == "http.route" {
			route = kv.Value.AsString()
		}
		if strings.Contains(kv.Value.String(), secret) {
			t.Errorf("server span attribute %s carries a credential: %s", kv.Key, kv.Value.String())
		}
	}
	is.Equal(route, "/api/v1/sboms/{id}")
}

func TestClientSpansDropQueryAndHeaders(t *testing.T) {
	is := is.New(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(tracing.RedactExporter(exp)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()

	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp) // tracing.Transport records on the global provider
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	client := &http.Client{Transport: tracing.Transport(srv.Client().Transport)}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v2/app/tags/list?access_token="+secret, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	is.NoErr(err)
	_ = resp.Body.Close()

	spans := exp.GetSpans()
	is.Equal(len(spans), 1)
	for _, kv := range spans[0].Attributes {
		if strings.Contains(kv.Value.String(), secret) {
			t.Errorf("client span attribute %s carries a credential: %s", kv.Key, kv.Value.String())
		}
		if kv.Key == "url.full" {
			is.Equal(kv.Value.AsString(), srv.URL+"/v2/app/tags/list") // query removed
		}
	}
}
