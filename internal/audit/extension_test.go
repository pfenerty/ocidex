package audit_test

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/audit"
	"github.com/pfenerty/ocidex/internal/event"
)

// capturingHandler is a slog.Handler that captures log records.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *capturingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(_ string) slog.Handler      { return h }

// attrMap extracts all attributes from a slog.Record into a map.
func attrMap(r slog.Record) map[string]any {
	m := make(map[string]any)
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})
	return m
}

func TestExtension_EventHandlers(t *testing.T) {
	sbomID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	artifactID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	tests := []struct {
		name             string
		eventType        event.Type
		data             any
		wantEventType    string
		wantResourceType string
		wantResourceID   string
	}{
		{
			name:      "sbom ingested",
			eventType: event.SBOMIngested,
			data: event.SBOMIngestedData{
				SBOMID:       sbomID,
				ArtifactName: "ubuntu",
				Digest:       "sha256:abc",
			},
			wantEventType:    "sbom.ingested",
			wantResourceType: "sbom",
			wantResourceID:   "01000000-0000-0000-0000-000000000000",
		},
		{
			name:      "sbom deleted",
			eventType: event.SBOMDeleted,
			data: event.SBOMDeletedData{
				SBOMID: sbomID,
			},
			wantEventType:    "sbom.deleted",
			wantResourceType: "sbom",
			wantResourceID:   "01000000-0000-0000-0000-000000000000",
		},
		{
			name:      "artifact deleted",
			eventType: event.ArtifactDeleted,
			data: event.ArtifactDeletedData{
				ArtifactID: artifactID,
			},
			wantEventType:    "artifact.deleted",
			wantResourceType: "artifact",
			wantResourceID:   "02000000-0000-0000-0000-000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)

			handler := &capturingHandler{}
			logger := slog.New(handler)
			ext := audit.NewExtension(logger)

			bus := event.NewBus(logger)
			is.NoErr(ext.Init(bus))

			bus.Publish(t.Context(), tt.eventType, tt.data)

			handler.mu.Lock()
			defer handler.mu.Unlock()

			is.Equal(len(handler.records), 1)
			rec := handler.records[0]
			is.Equal(rec.Message, "audit")
			is.Equal(rec.Level, slog.LevelInfo)

			attrs := attrMap(rec)
			is.Equal(attrs["event_type"], tt.wantEventType)
			is.Equal(attrs["resource_type"], tt.wantResourceType)
			is.Equal(attrs["resource_id"], tt.wantResourceID)
			is.True(attrs["metadata"] != nil)
		})
	}
}

func TestExtension_Name(t *testing.T) {
	is := is.New(t)
	ext := audit.NewExtension(slog.Default())
	is.Equal(ext.Name(), "audit")
}
