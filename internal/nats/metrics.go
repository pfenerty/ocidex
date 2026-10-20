package nats

import (
	"context"
	"log/slog"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/pfenerty/ocidex/internal/metrics"
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

// PublishMsg publishes msg and waits for the stream's ack, counting the
// outcome. Use it instead of JS.PublishMsg so the publish is measured.
func (c *Client) PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	ack, err := c.JS.PublishMsg(ctx, msg, opts...)
	if err != nil {
		c.recordPublish(ctx, msg.Subject, outcomeError)
		return nil, err
	}
	c.recordPublish(ctx, msg.Subject, ackOutcome(ack))
	return ack, nil
}

// PublishMsgAsync publishes msg without waiting, counting the outcome when the
// ack (or its failure) arrives. Every future resolves: Connect sets an async
// publish timeout.
func (c *Client) PublishMsgAsync(msg *nats.Msg, opts ...jetstream.PublishOpt) (jetstream.PubAckFuture, error) {
	future, err := c.JS.PublishMsgAsync(msg, opts...)
	if err != nil {
		c.recordPublish(context.Background(), msg.Subject, outcomeError)
		return nil, err
	}
	if c.publishes != nil {
		go func() {
			select {
			case ack := <-future.Ok():
				c.recordPublish(context.Background(), msg.Subject, ackOutcome(ack))
			case err := <-future.Err():
				slog.Debug("nats async publish failed", "subject_class", subjectClass(msg.Subject), "err", err)
				c.recordPublish(context.Background(), msg.Subject, outcomeError)
			}
		}()
	}
	return future, nil
}
