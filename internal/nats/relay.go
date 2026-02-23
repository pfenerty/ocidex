package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/event"
)

// Envelope is the wire format for all outbound NATS messages.
type Envelope struct {
	EventType  string          `json:"event_type"`
	OccurredAt time.Time       `json:"occurred_at"`
	Payload    json.RawMessage `json:"payload"`
}

// Per-event wire structs convert pgtype.UUID to string.

type sbomIngestedWire struct {
	SBOMID         string `json:"sbom_id"`
	ArtifactType   string `json:"artifact_type"`
	ArtifactName   string `json:"artifact_name"`
	Digest         string `json:"digest"`
	SubjectVersion string `json:"subject_version"`
}

type sbomDeletedWire struct {
	SBOMID string `json:"sbom_id"`
}

type artifactDeletedWire struct {
	ArtifactID string `json:"artifact_id"`
}

var subjectMap = map[event.Type]string{
	event.SBOMIngested:    "sbom.ingested",
	event.SBOMDeleted:     "sbom.deleted",
	event.ArtifactCreated: "artifact.created",
	event.ArtifactDeleted: "artifact.deleted",
}

// RelayExtension subscribes to the in-process bus and forwards events to JetStream.
// It is best-effort: relay failures are logged but never block the HTTP handler.
type RelayExtension struct {
	client     *Client
	streamName string
	logger     *slog.Logger
}

// NewRelayExtension creates a relay extension backed by the given Client.
// Uses "ocidex" as the stream name prefix.
func NewRelayExtension(client *Client, logger *slog.Logger) *RelayExtension {
	return &RelayExtension{client: client, streamName: "ocidex", logger: logger}
}

// NewRelayExtensionWithStream creates a relay extension with an explicit stream name prefix.
func NewRelayExtensionWithStream(client *Client, streamName string, logger *slog.Logger) *RelayExtension {
	return &RelayExtension{client: client, streamName: streamName, logger: logger}
}

// Name returns the extension identifier.
func (r *RelayExtension) Name() string { return "nats-relay" }

// Init subscribes to all event types.
func (r *RelayExtension) Init(bus *event.Bus) error {
	bus.Subscribe(event.SBOMIngested, r.handleEvent)
	bus.Subscribe(event.SBOMDeleted, r.handleEvent)
	bus.Subscribe(event.ArtifactCreated, r.handleEvent)
	bus.Subscribe(event.ArtifactDeleted, r.handleEvent)
	return nil
}

// Start is a no-op; the handler runs synchronously on the bus goroutine.
func (r *RelayExtension) Start(_ context.Context) error { return nil }

// Stop is a no-op; connection lifecycle is owned by Client.
func (r *RelayExtension) Stop() error { return nil }

func (r *RelayExtension) handleEvent(_ context.Context, ev event.Event) {
	subjectSuffix, ok := subjectMap[ev.Type]
	if !ok {
		return
	}

	payload, err := marshalPayload(ev)
	if err != nil {
		r.logger.Error("nats relay: marshal payload", "event_type", ev.Type, "err", err)
		return
	}

	env := Envelope{
		EventType:  string(ev.Type),
		OccurredAt: time.Now().UTC(),
		Payload:    payload,
	}

	data, err := json.Marshal(env)
	if err != nil {
		r.logger.Error("nats relay: marshal envelope", "event_type", ev.Type, "err", err)
		return
	}

	subject := r.streamName + "." + subjectSuffix
	if _, err := r.client.JS.PublishAsync(subject, data); err != nil {
		r.logger.Error("nats relay: publish", "subject", subject, "err", err)
	}
}

func marshalPayload(ev event.Event) (json.RawMessage, error) {
	switch d := ev.Data.(type) {
	case event.SBOMIngestedData:
		return json.Marshal(sbomIngestedWire{
			SBOMID:         uuidToString(d.SBOMID),
			ArtifactType:   d.ArtifactType,
			ArtifactName:   d.ArtifactName,
			Digest:         d.Digest,
			SubjectVersion: d.SubjectVersion,
		})
	case event.SBOMDeletedData:
		return json.Marshal(sbomDeletedWire{
			SBOMID: uuidToString(d.SBOMID),
		})
	case event.ArtifactDeletedData:
		return json.Marshal(artifactDeletedWire{
			ArtifactID: uuidToString(d.ArtifactID),
		})
	default:
		// ArtifactCreated or unknown — marshal as-is (nil becomes null).
		return json.Marshal(d)
	}
}

func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

