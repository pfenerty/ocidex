package tracing

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/propagation"
)

// w3c is the propagator for contexts stored on rows. It is fixed, not the
// global one, so what a row holds never depends on how a binary set up
// propagation.
var w3c = propagation.TraceContext{}

// Inject encodes ctx's span context for a job row's trace_context column
// (ADR-0055 T3): "traceparent", or "traceparent\ntracestate". It is empty
// when ctx has no valid span context, which is always the case with tracing
// off.
func Inject(ctx context.Context) string {
	c := propagation.MapCarrier{}
	w3c.Inject(ctx, c)
	tp := c.Get("traceparent")
	if tp == "" {
		return ""
	}
	if ts := c.Get("tracestate"); ts != "" {
		return tp + "\n" + ts
	}
	return tp
}

// Extract returns ctx carrying the remote span context Inject encoded in s, or
// ctx unchanged when s is empty or malformed.
func Extract(ctx context.Context, s string) context.Context {
	if s == "" {
		return ctx
	}
	tp, ts, _ := strings.Cut(s, "\n")
	return w3c.Extract(ctx, propagation.MapCarrier{"traceparent": tp, "tracestate": ts})
}
