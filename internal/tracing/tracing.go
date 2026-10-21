// Package tracing builds each binary's OpenTelemetry TracerProvider (ADR-0055
// T1) and ties log records to the span they were written in (T6).
//
// Tracing is off unless OTEL_TRACES_EXPORTER names an exporter; until then the
// provider is a no-op and a span costs a context lookup. Packages take a
// trace.TracerProvider in their constructors, as they take a MeterProvider.
package tracing

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pfenerty/ocidex/internal/metrics"
)

// DefaultSampleRatio is the share of new traces kept when OTEL_TRACES_SAMPLER
// is unset (ADR-0055 T4). Spans with a parent follow the parent's decision.
const DefaultSampleRatio = 0.1

// Tracer is a shorthand for the instrumentation scope OCIDex packages use.
func Tracer(tp trace.TracerProvider) trace.Tracer {
	return tp.Tracer("github.com/pfenerty/ocidex")
}

// enabled reports whether OTEL_TRACES_EXPORTER asks for spans to be exported.
func enabled() bool {
	v := os.Getenv("OTEL_TRACES_EXPORTER")
	return v != "" && v != "none"
}

// New builds the TracerProvider for serviceName, or returns nil and no error
// when tracing is off. The exporter, endpoint and sampler come from the
// standard OTEL_* variables.
func New(ctx context.Context, serviceName string) (*sdktrace.TracerProvider, error) {
	if !enabled() {
		return nil, nil
	}
	exp, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return nil, fmt.Errorf("span exporter: %w", err)
	}
	res, err := metrics.Resource(ctx, serviceName)
	if err != nil {
		return nil, err
	}
	opts := []sdktrace.TracerProviderOption{sdktrace.WithResource(res), sdktrace.WithBatcher(exp)}
	// An explicit sampler would override OTEL_TRACES_SAMPLER, so it is set only
	// when the variable is not.
	if os.Getenv("OTEL_TRACES_SAMPLER") == "" {
		opts = append(opts, sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(DefaultSampleRatio))))
	}
	return sdktrace.NewTracerProvider(opts...), nil
}

// Start builds the TracerProvider for serviceName, makes it and the W3C
// propagator global, and returns it with a func that flushes and stops it. If
// tracing is off, or setup fails (logged: losing traces must not take a binary
// down), it returns a no-op provider. The propagator is set either way, so
// context still crosses process boundaries for a downstream that traces.
func Start(ctx context.Context, serviceName string) (trace.TracerProvider, func()) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	tp, err := New(ctx, serviceName)
	if err != nil {
		slog.Error("tracing disabled", "err", err)
	}
	if tp == nil {
		return noop.NewTracerProvider(), func() {}
	}
	otel.SetTracerProvider(tp)
	slog.Info("tracing enabled", "exporter", os.Getenv("OTEL_TRACES_EXPORTER"))
	return tp, func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(stopCtx); err != nil {
			slog.Error("tracing shutdown", "err", err)
		}
	}
}
