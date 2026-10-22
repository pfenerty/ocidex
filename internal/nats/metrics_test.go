package nats

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestSubjectClass(t *testing.T) {
	is := is.New(t)
	is.Equal(subjectClass("ocidex.scan.hint"), "scan.hint")
	is.Equal(subjectClass("prod-stream.enrich.hint"), "enrich.hint")
	is.Equal(subjectClass("ocidex.catalog.walk.requested"), "catalog.walk.requested")
	is.Equal(subjectClass("ocidex.sbom.ingested"), "sbom.ingested")
	is.Equal(subjectClass("ocidex.sbom.0f3a"), "other") // never a raw subject
	is.Equal(subjectClass("nostream"), "other")
}

// stubJS answers publishes with a fixed ack or error. Methods it does not
// override panic through the nil embedded interface.
type stubJS struct {
	jetstream.JetStream
	ack *jetstream.PubAck
	err error
}

func (s stubJS) PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	return s.ack, s.err
}

func (s stubJS) PublishMsgAsync(msg *nats.Msg, _ ...jetstream.PublishOpt) (jetstream.PubAckFuture, error) {
	f := stubFuture{msg: msg, ok: make(chan *jetstream.PubAck, 1), errc: make(chan error, 1)}
	if s.err != nil {
		f.errc <- s.err
	} else {
		f.ok <- s.ack
	}
	return f, nil
}

type stubFuture struct {
	msg  *nats.Msg
	ok   chan *jetstream.PubAck
	errc chan error
}

func (f stubFuture) Ok() <-chan *jetstream.PubAck { return f.ok }
func (f stubFuture) Err() <-chan error            { return f.errc }
func (f stubFuture) Msg() *nats.Msg               { return f.msg }

func publishCounts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "ocidex.nats.publishes" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				class, _ := dp.Attributes.Value(attribute.Key("subject_class"))
				outcome, _ := dp.Attributes.Value(attribute.Key("outcome"))
				out[class.AsString()+" "+outcome.AsString()] = dp.Value
			}
		}
	}
	return out
}

func TestPublishMetrics(t *testing.T) {
	is := is.New(t)
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	msg := func(subject string) *nats.Msg { return &nats.Msg{Subject: subject} }

	ok := (&Client{JS: stubJS{ack: &jetstream.PubAck{}}}).WithMetrics(mp)
	dup := (&Client{JS: stubJS{ack: &jetstream.PubAck{Duplicate: true}}}).WithMetrics(mp)
	bad := (&Client{JS: stubJS{err: errors.New("no responders")}}).WithMetrics(mp)

	_, err := ok.PublishMsg(t.Context(), msg("ocidex.scan.hint"))
	is.NoErr(err)
	_, err = dup.PublishMsg(t.Context(), msg("ocidex.catalog.walk.requested"))
	is.NoErr(err)
	_, err = bad.PublishMsg(t.Context(), msg("ocidex.scan.hint"))
	is.True(err != nil)
	_, err = ok.PublishMsgAsync(t.Context(), msg("ocidex.enrich.hint"))
	is.NoErr(err)
	_, err = bad.PublishMsgAsync(t.Context(), msg("ocidex.enrich.hint"))
	is.NoErr(err) // the failure arrives on the future

	want := map[string]int64{
		"scan.hint ok":                     1,
		"scan.hint error":                  1,
		"catalog.walk.requested duplicate": 1,
		"enrich.hint ok":                   1,
		"enrich.hint error":                1,
	}
	deadline := time.Now().Add(2 * time.Second) // async outcomes land from a goroutine
	got := publishCounts(t, reader)
	for len(got) < len(want) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		got = publishCounts(t, reader)
	}
	is.Equal(got, want)
}

func TestPublishWithoutMetrics(t *testing.T) {
	is := is.New(t)
	c := &Client{JS: stubJS{ack: &jetstream.PubAck{}}}
	_, err := c.PublishMsg(t.Context(), &nats.Msg{Subject: "ocidex.scan.hint"})
	is.NoErr(err) // no counter configured: publishing still works
}

func TestPublishInjectsTraceContext(t *testing.T) {
	is := is.New(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp) // the client records on the global provider
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	ctx, parent := tp.Tracer("test").Start(context.Background(), "walk request")
	msg := &nats.Msg{Subject: "ocidex.catalog.walk.requested"}
	_, err := (&Client{JS: stubJS{ack: &jetstream.PubAck{}}}).PublishMsg(ctx, msg)
	is.NoErr(err)
	parent.End()

	var publish sdktrace.ReadOnlySpan
	for _, s := range exp.GetSpans().Snapshots() {
		if s.Name() == "publish catalog.walk.requested" {
			publish = s
		}
	}
	is.True(publish != nil)
	is.Equal(publish.SpanKind(), trace.SpanKindProducer)
	is.Equal(publish.Parent().SpanID(), parent.SpanContext().SpanID())
	// The header carries the publish span, so a consumer becomes its child.
	got := propagation.TraceContext{}.Extract(context.Background(), propagation.HeaderCarrier(msg.Header))
	is.Equal(trace.SpanContextFromContext(got).SpanID(), publish.SpanContext().SpanID())
}
