package tracing

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Transport wraps rt so each outbound request gets a client span (ADR-0055
// T2). It records spans on the global TracerProvider, which Start sets, so
// clients built deep in a package need no provider passed down; with tracing
// off the global one is a no-op. rt itself is never modified, and nil means
// http.DefaultTransport, which is wrapped, not replaced.
//
// HTTP client metrics are off: ADR-0054 M5 does not list them.
func Transport(rt http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(rt, otelhttp.WithMeterProvider(metricnoop.NewMeterProvider()))
}

// Client is http.Client with its transport wrapped by Transport. The returned
// client is a copy; c is unchanged.
func Client(c *http.Client) *http.Client {
	out := *c
	out.Transport = Transport(c.Transport)
	return &out
}

// RedactExporter wraps exp so no exported span carries what ADR-0055 T5
// forbids, whoever created the span and whenever the attribute was set: the
// query, fragment and userinfo of url.full, and any recorded header.
func RedactExporter(exp sdktrace.SpanExporter) sdktrace.SpanExporter {
	return redactingExporter{exp}
}

type redactingExporter struct{ sdktrace.SpanExporter }

func (e redactingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = redact(s)
	}
	return e.SpanExporter.ExportSpans(ctx, out)
}

// redactedSpan is s with its attributes replaced. Embedding the interface keeps
// every other accessor, including the SDK's unexported marker method.
type redactedSpan struct {
	sdktrace.ReadOnlySpan
	attrs []attribute.KeyValue
}

func (s redactedSpan) Attributes() []attribute.KeyValue { return s.attrs }

func redact(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	attrs := s.Attributes()
	var out []attribute.KeyValue
	for i, kv := range attrs {
		clean, changed := redactAttr(kv)
		if !changed {
			continue
		}
		if out == nil {
			out = append([]attribute.KeyValue(nil), attrs...)
		}
		out[i] = clean
	}
	if out == nil {
		return s
	}
	return redactedSpan{s, out}
}

func redactAttr(kv attribute.KeyValue) (attribute.KeyValue, bool) {
	key := string(kv.Key)
	switch {
	case key == "url.full":
		u, err := url.Parse(kv.Value.AsString())
		if err != nil {
			return attribute.String(key, "[REDACTED]"), true
		}
		if u.RawQuery == "" && u.Fragment == "" && u.User == nil {
			return kv, false
		}
		u.RawQuery, u.Fragment, u.User = "", "", nil
		u.ForceQuery = false
		return attribute.String(key, u.String()), true
	case strings.HasPrefix(key, "http.request.header.") || strings.HasPrefix(key, "http.response.header."):
		return attribute.String(key, "[REDACTED]"), true
	}
	return kv, false
}
