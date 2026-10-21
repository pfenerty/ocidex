package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/pfenerty/ocidex/internal/metrics"
)

// routeUnmatched is the http.route of a request no route matched, so a path
// scan adds one series rather than one per path (ADR-0054 M4).
const routeUnmatched = "unmatched"

// routePattern returns chi's pattern for the route that served r, such as
// /api/v1/sboms/{id}. RouteContext is only populated once the router has
// matched, so callers read it after calling next.
func routePattern(r *http.Request) (string, bool) {
	if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePattern() != "" {
		return rctx.RoutePattern(), true
	}
	return "", false
}

// standardMethods are the http.request.method values the semantic conventions
// keep as-is. Anything else is recorded as _OTHER, so a client inventing
// methods cannot add series.
var standardMethods = map[string]bool{
	http.MethodConnect: true, http.MethodDelete: true, http.MethodGet: true,
	http.MethodHead: true, http.MethodOptions: true, http.MethodPatch: true,
	http.MethodPost: true, http.MethodPut: true, http.MethodTrace: true,
}

// untraced are the probe routes: they would be most of the spans and none of
// the interest (ADR-0055 T4).
var untraced = map[string]bool{"/health": true, "/ready": true}

// RequestSpans returns middleware that starts a server span per request on tp,
// continuing a caller's W3C trace context (ADR-0055 T2). RequestMetrics names
// the span after routing. otelhttp's own HTTP metrics are off: RequestMetrics
// records the one ADR-0054 lists.
func RequestSpans(tp trace.TracerProvider) func(http.Handler) http.Handler {
	return otelhttp.NewMiddleware("http.server",
		otelhttp.WithTracerProvider(tp),
		// Explicit rather than the global one, so a caller's trace is continued
		// however the binary set up propagation.
		otelhttp.WithPropagators(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})),
		otelhttp.WithMeterProvider(metricnoop.NewMeterProvider()),
		otelhttp.WithFilter(func(r *http.Request) bool { return !untraced[r.URL.Path] }),
	)
}

// RequestMetrics returns middleware that records http.server.request.duration
// for every request, labelled by method, route pattern and status code
// (ADR-0054 M5). The request count is the histogram's count. It also names
// the request's span by method and route pattern.
func RequestMetrics(mp metric.MeterProvider) func(http.Handler) http.Handler {
	duration, err := metrics.Meter(mp).Float64Histogram("http.server.request.duration",
		metric.WithDescription("Duration of HTTP server requests."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(metrics.DurationBuckets...),
	)
	if err != nil {
		slog.Error("http request metrics disabled", "err", err)
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			route, ok := routePattern(r)
			if !ok {
				route = routeUnmatched
			}
			method := r.Method
			if !standardMethods[method] {
				method = "_OTHER"
			}
			// The server span started before routing; now the pattern is known.
			span := trace.SpanFromContext(r.Context())
			span.SetName(method + " " + route)
			span.SetAttributes(attribute.String("http.route", route))
			status := ww.Status()
			if status == 0 {
				status = http.StatusOK // nothing written: net/http sends 200
			}
			duration.Record(r.Context(), time.Since(start).Seconds(), metric.WithAttributes(
				attribute.String("http.request.method", method),
				attribute.String("http.route", route),
				attribute.Int("http.response.status_code", status),
			))
		})
	}
}
