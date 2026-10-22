package nats

import (
	"context"
	"log/slog"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/pfenerty/ocidex/internal/metrics"
	"github.com/pfenerty/ocidex/internal/tracing"
)

// Publish outcomes for ocidex.nats.publishes (ADR-0054 M5). duplicate is an ack
// for a Nats-Msg-Id the stream already holds, inside its dedup window.
const (
	outcomeOK        = "ok"
	outcomeDuplicate = "duplicate"
	outcomeError     = "error"
)

// subjectClasses are the subjects OCIDex publishes, after the stream name.
// They are the only subject_class values, so the label stays bounded; any
// other subject is "other" (ADR-0054 M4).
var subjectClasses = map[string]bool{
	"scan.hint":              true,
	"enrich.hint":            true,
	"catalog.walk.requested": true,
	"sbom.ingested":          true,
	"sbom.deleted":           true,
	"artifact.created":       true,
	"artifact.deleted":       true,
}

// subjectClass returns the bounded class of subject: the part after the
// stream name when it is one OCIDex publishes, else "other".
func subjectClass(subject string) string {
	_, rest, ok := strings.Cut(subject, ".")
	if ok && subjectClasses[rest] {
		return rest
	}
	return "other"
}

// WithMetrics counts this client's publishes on mp. Call it before publishing.
func (c *Client) WithMetrics(mp metric.MeterProvider) *Client {
	counter, err := metrics.Meter(mp).Int64Counter("ocidex.nats.publishes",
		metric.WithDescription("JetStream publishes, by subject class and outcome."),
		metric.WithUnit("{message}"))
	if err == nil {
		c.publishes = counter
	}
	return c
}

func (c *Client) recordPublish(ctx context.Context, subject, outcome string) {
	if c.publishes == nil {
		return
	}
	c.publishes.Add(ctx, 1, metric.WithAttributes(
		attribute.String("subject_class", subjectClass(subject)),
		attribute.String("outcome", outcome),
	))
}

func ackOutcome(ack *jetstream.PubAck) string {
	if ack != nil && ack.Duplicate {
		return outcomeDuplicate
	}
	return outcomeOK
}

// startPublishSpan starts a producer span for msg and writes the trace context
// into its headers (ADR-0055 T2), so a consumer that reads them, such as the
// catalog-walk consumer, continues the trace. It records on the global
// TracerProvider, as tracing.Transport does.
func startPublishSpan(ctx context.Context, msg *nats.Msg) (context.Context, trace.Span) {
	class := subjectClass(msg.Subject)
	ctx, span := tracing.Tracer(otel.GetTracerProvider()).Start(ctx, "publish "+class,
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			attribute.String("messaging.system", "nats"),
			attribute.String("messaging.destination.name", class),
		))
	if msg.Header == nil {
		msg.Header = nats.Header{}
	}
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(msg.Header))
	return ctx, span
}

func endPublishSpan(span trace.Span, outcome string, err error) {
	span.SetAttributes(attribute.String("ocidex.nats.outcome", outcome))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "publish failed")
	}
	span.End()
}

// PublishMsg publishes msg and waits for the stream's ack, counting the
// outcome. Use it instead of JS.PublishMsg so the publish is measured and
// traced.
func (c *Client) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	ctx, span := startPublishSpan(ctx, msg)
	ack, err := c.JS.PublishMsg(ctx, msg, opts...)
	if err != nil {
		c.recordPublish(ctx, msg.Subject, outcomeError)
		endPublishSpan(span, outcomeError, err)
		return nil, err
	}
	c.recordPublish(ctx, msg.Subject, ackOutcome(ack))
	endPublishSpan(span, ackOutcome(ack), nil)
	return ack, nil
}

// PublishMsgAsync publishes msg without waiting, counting the outcome and
// ending its span when the ack (or its failure) arrives. Every future
// resolves: Connect sets an async publish timeout. ctx parents the span; the
// publish itself is not bound to it, and the ack usually arrives after the
// caller's request has ended, so the wait keeps ctx's values but not its
// cancellation.
func (c *Client) PublishMsgAsync(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (jetstream.PubAckFuture, error) {
	ctx, span := startPublishSpan(ctx, msg)
	ackCtx := context.WithoutCancel(ctx)
	future, err := c.JS.PublishMsgAsync(msg, opts...)
	if err != nil {
		c.recordPublish(ackCtx, msg.Subject, outcomeError)
		endPublishSpan(span, outcomeError, err)
		return nil, err
	}
	go func() {
		select {
		case ack := <-future.Ok():
			c.recordPublish(ackCtx, msg.Subject, ackOutcome(ack))
			endPublishSpan(span, ackOutcome(ack), nil)
		case err := <-future.Err():
			slog.DebugContext(ackCtx, "nats async publish failed", "subject_class", subjectClass(msg.Subject), "err", err)
			c.recordPublish(ackCtx, msg.Subject, outcomeError)
			endPublishSpan(span, outcomeError, err)
		}
	}()
	return future, nil
}
