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
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
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

// Resource describes the binary named serviceName (for example "ocidex-api"):
// service.name, service.version and any OTEL_RESOURCE_ATTRIBUTES. Metrics and
// traces share it (ADR-0055 T1).
func Resource(ctx context.Context, serviceName string) (*resource.Resource, error) {
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version.Version),
	))
	if err != nil {
		return nil, fmt.Errorf("telemetry resource: %w", err)
	}
	if env, err := resource.New(ctx, resource.WithFromEnv()); err == nil {
		res, _ = resource.Merge(res, env)
	}
	return res, nil
}

// exporters returns the OTEL_METRICS_EXPORTER entries: prometheus (the
// default) serves /metrics, otlp pushes to OTEL_EXPORTER_OTLP_*, none disables
// both. Several may be listed, comma-separated.
func exporters() (map[string]bool, error) {
	v := strings.TrimSpace(os.Getenv("OTEL_METRICS_EXPORTER"))
	if v == "" {
		v = "prometheus"
	}
	out := map[string]bool{}
	for _, name := range strings.Split(v, ",") {
		name = strings.TrimSpace(name)
		switch name {
		case "prometheus", "otlp", "none":
			out[name] = true
		default:
			return nil, fmt.Errorf("OTEL_METRICS_EXPORTER: unsupported exporter %q (want prometheus, otlp or none)", name)
		}
	}
	if out["none"] && len(out) > 1 {
		return nil, errors.New("OTEL_METRICS_EXPORTER: none cannot be combined with other exporters")
	}
	return out, nil
}

// otlpReader pushes metrics over OTLP, using OTEL_EXPORTER_OTLP_METRICS_PROTOCOL
// or OTEL_EXPORTER_OTLP_PROTOCOL (default http/protobuf) and the exporters'
// own OTEL_EXPORTER_OTLP_* settings.
func otlpReader(ctx context.Context) (sdkmetric.Reader, error) {
	proto := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL")
	if proto == "" {
		proto = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	var (
		exp sdkmetric.Exporter
		err error
	)
	switch proto {
	case "", "http/protobuf":
		exp, err = otlpmetrichttp.New(ctx)
	case "grpc":
		exp, err = otlpmetricgrpc.New(ctx)
	default:
		return nil, fmt.Errorf("OTLP metrics: unsupported protocol %q (want http/protobuf or grpc)", proto)
	}
	if err != nil {
		return nil, fmt.Errorf("OTLP metrics exporter: %w", err)
	}
	return sdkmetric.NewPeriodicReader(exp), nil
}

// New builds the Provider for the binary named serviceName. Go runtime and
// process metrics are included. Handler is nil when OTEL_METRICS_EXPORTER
// leaves out prometheus.
func New(ctx context.Context, serviceName string) (*Provider, error) {
	enabled, err := exporters()
	if err != nil {
		return nil, err
	}
	res, err := Resource(ctx, serviceName)
	if err != nil {
		return nil, err
	}

	opts := []sdkmetric.Option{sdkmetric.WithResource(res)}
	var handler http.Handler
	if enabled["prometheus"] {
		// A private registry, so a dependency registering on the global one
		// cannot add series OCIDex never chose.
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
		opts = append(opts, sdkmetric.WithReader(exporter))
		// OpenMetrics, when the scraper asks for it, is the format that carries
		// exemplars (ADR-0055 T6).
		handler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{EnableOpenMetrics: true})
	}
	if enabled["otlp"] {
		r, err := otlpReader(ctx)
		if err != nil {
			return nil, err
		}
		opts = append(opts, sdkmetric.WithReader(r))
	}

	mp := sdkmetric.NewMeterProvider(opts...)
	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		return nil, errors.Join(fmt.Errorf("runtime metrics: %w", err), mp.Shutdown(ctx))
	}
	return &Provider{MeterProvider: mp, handler: handler}, nil
}

// Handler serves the Prometheus text format at whatever path it is mounted on,
// or is nil when Prometheus export is off.
func (p *Provider) Handler() http.Handler { return p.handler }

// Meter is a shorthand for the instrumentation scope OCIDex packages use.
func Meter(mp metric.MeterProvider) metric.Meter {
	return mp.Meter("github.com/pfenerty/ocidex")
}

// Start builds the Provider for serviceName. If that fails it logs why and
// returns a no-op provider and a nil handler: losing metrics must not take a
// binary down. The handler is also nil when Prometheus export is off. The
// returned func flushes and stops the provider.
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
