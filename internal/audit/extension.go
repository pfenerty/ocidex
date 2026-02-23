// Package audit implements an extension that emits structured audit log lines
// for every event published on the event bus.
package audit

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/event"
)

// Extension emits structured slog audit entries for every event on the bus.
type Extension struct {
	logger *slog.Logger
}

// NewExtension creates an audit logging extension.
func NewExtension(logger *slog.Logger) *Extension {
	return &Extension{logger: logger}
}

// Name returns the extension identifier.
func (e *Extension) Name() string { return "audit" }

// Init subscribes to all event types.
func (e *Extension) Init(bus *event.Bus) error {
	bus.Subscribe(event.SBOMIngested, e.handleSBOMIngested)
	bus.Subscribe(event.SBOMDeleted, e.handleSBOMDeleted)
	bus.Subscribe(event.ArtifactCreated, e.handleArtifactCreated)
	bus.Subscribe(event.ArtifactDeleted, e.handleArtifactDeleted)
	return nil
}

// Start is a no-op; audit handlers are synchronous.
func (e *Extension) Start(_ context.Context) error { return nil }

// Stop is a no-op.
func (e *Extension) Stop() error { return nil }

func (e *Extension) handleSBOMIngested(ctx context.Context, ev event.Event) {
	data, ok := ev.Data.(event.SBOMIngestedData)
	if !ok {
		e.logger.Error("audit: unexpected data type for sbom.ingested")
		return
	}
	e.record(ctx, string(event.SBOMIngested), "sbom", data.SBOMID, data)
}

func (e *Extension) handleSBOMDeleted(ctx context.Context, ev event.Event) {
	data, ok := ev.Data.(event.SBOMDeletedData)
	if !ok {
		e.logger.Error("audit: unexpected data type for sbom.deleted")
		return
	}
	e.record(ctx, string(event.SBOMDeleted), "sbom", data.SBOMID, data)
}

func (e *Extension) handleArtifactCreated(ctx context.Context, ev event.Event) {
	// ArtifactCreated is defined but not yet published with a typed data struct.
	// Log with nil metadata until a data type is added.
	e.record(ctx, string(event.ArtifactCreated), "artifact", pgtype.UUID{}, ev.Data)
}

func (e *Extension) handleArtifactDeleted(ctx context.Context, ev event.Event) {
	data, ok := ev.Data.(event.ArtifactDeletedData)
	if !ok {
		e.logger.Error("audit: unexpected data type for artifact.deleted")
		return
	}
	e.record(ctx, string(event.ArtifactDeleted), "artifact", data.ArtifactID, data)
}

func (e *Extension) record(ctx context.Context, eventType, resourceType string, resourceID pgtype.UUID, payload any) {
	e.logger.InfoContext(ctx, "audit",
		"event_type", eventType,
		"resource_type", resourceType,
		"resource_id", uuidToString(resourceID),
		"metadata", payload,
	)
}

func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
