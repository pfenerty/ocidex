package tracing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/matryer/is"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/pfenerty/ocidex/internal/tracing"
)

func TestOffByDefault(t *testing.T) {
	is := is.New(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "")
	tp, err := tracing.New(t.Context(), "ocidex-test")
	is.NoErr(err)
	is.True(tp == nil)

	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	tp, err = tracing.New(t.Context(), "ocidex-test")
	is.NoErr(err)
	is.True(tp == nil)
}

func TestConsoleExporter(t *testing.T) {
	is := is.New(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "console")
	tp, err := tracing.New(t.Context(), "ocidex-test")
	is.NoErr(err)
	is.True(tp != nil)
	is.NoErr(tp.Shutdown(t.Context()))
}

func TestDefaultSamplerIsParentBasedRatio(t *testing.T) {
	is := is.New(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "console")
	t.Setenv("OTEL_TRACES_SAMPLER", "")
	tp, err := tracing.New(t.Context(), "ocidex-test")
	is.NoErr(err)
	defer func() { _ = tp.Shutdown(t.Context()) }()
	tracer := tracing.Tracer(tp)

	sampled := 0
	for range 2000 {
		_, span := tracer.Start(context.Background(), "root")
		if span.SpanContext().IsSampled() {
			sampled++
		}
		span.End()
	}
	is.True(sampled > 100 && sampled < 300) // ~10% of new traces

	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled, Remote: true,
	})
	_, child := tracer.Start(trace.ContextWithRemoteSpanContext(context.Background(), parent), "child")
	is.True(child.SpanContext().IsSampled()) // a sampled parent's child is always kept
	child.End()
}

func TestLogHandlerAddsTraceIDs(t *testing.T) {
	is := is.New(t)
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(tracetest.NewInMemoryExporter())))
	var buf bytes.Buffer
	log := slog.New(tracing.LogHandler(slog.NewJSONHandler(&buf, nil))).With("component", "test")

	ctx, span := tracing.Tracer(tp).Start(context.Background(), "op")
	log.InfoContext(ctx, "inside")
	span.End()
	log.InfoContext(context.Background(), "outside")

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	is.Equal(len(lines), 2)
	var inside, outside map[string]any
	is.NoErr(json.Unmarshal(lines[0], &inside))
	is.NoErr(json.Unmarshal(lines[1], &outside))
	is.Equal(inside["trace_id"], span.SpanContext().TraceID().String())
	is.Equal(inside["span_id"], span.SpanContext().SpanID().String())
	is.Equal(inside["component"], "test") // WithAttrs keeps the wrapper
	_, has := outside["trace_id"]
	is.True(!has)
}
