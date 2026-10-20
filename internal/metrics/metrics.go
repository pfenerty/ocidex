// Package metrics builds each binary's OpenTelemetry MeterProvider and the
// Prometheus /metrics handler that serves it (ADR-0054 M1).
//
// Packages that record metrics take a metric.MeterProvider in their
// constructors and never read the global one, so tests can hand them a
// ManualReader-backed provider or a no-op one.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/pfenerty/ocidex/internal/version"
)

// DurationBuckets are the histogram boundaries, in seconds, for every duration
// instrument (ADR-0054 M3). The 5s boundary is the API's slow-request
// threshold. They are set on each instrument because the SDK's defaults assume
// milliseconds.
var DurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// Provider is a binary's MeterProvider and the handler that serves it.
type Provider struct {
	*sdkmetric.MeterProvider
	handler http.Handler
}

// New builds the Provider for the binary named serviceName (for example
// "ocidex-api"). The resource carries service.name, service.version and any
// OTEL_RESOURCE_ATTRIBUTES. Go runtime and process metrics are included.
func New(ctx context.Context, serviceName string) (*Provider, error) {
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version.Version),
	))
	if err != nil {
		return nil, fmt.Errorf("metrics resource: %w", err)
	}
	if env, err := resource.New(ctx, resource.WithFromEnv()); err == nil {
		res, _ = resource.Merge(res, env)
	}

	// A private registry, so a dependency registering on the global one cannot
	// add series OCIDex never chose.
	reg := prometheus.NewRegistry()
	if err := reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
		return nil, fmt.Errorf("process collector: %w", err)
	}
	exporter, err := otelprom.New(
		otelprom.WithRegisterer(reg),
		otelprom.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithSuffixes),
		otelprom.WithoutScopeInfo(),
	)
	if err != nil {
		return nil, fmt.Errorf("prometheus exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(exporter))
	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		return nil, errors.Join(fmt.Errorf("runtime metrics: %w", err), mp.Shutdown(ctx))
	}
	return &Provider{
		MeterProvider: mp,
		handler:       promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
	}, nil
}

// Handler serves the Prometheus text format at whatever path it is mounted on.
func (p *Provider) Handler() http.Handler { return p.handler }

// Meter is a shorthand for the instrumentation scope OCIDex packages use.
func Meter(mp metric.MeterProvider) metric.Meter {
	return mp.Meter("github.com/pfenerty/ocidex")
}

// Start builds the Provider for serviceName. If that fails it logs why and
// returns a no-op provider and a nil handler: losing metrics must not take a
// binary down. The returned func flushes and stops the provider.
func Start(ctx context.Context, serviceName string) (metric.MeterProvider, http.Handler, func()) {
	p, err := New(ctx, serviceName)
	if err != nil {
		slog.Error("metrics disabled", "err", err)
		return noop.NewMeterProvider(), nil, func() {}
	}
	return p, p.Handler(), func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.Shutdown(stopCtx); err != nil {
			slog.Error("metrics shutdown", "err", err)
		}
	}
}
