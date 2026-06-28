package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go"

	"github.com/pfenerty/ocidex/internal/event"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/service"
)

// NATSSubmitter subscribes to in-process SBOMIngested events, writes an
// enrichment_jobs row to the DB, and publishes a best-effort NATS hint.
// It implements extension.Extension and is registered on the API server.
//
// The DB row is the source of truth. If the hint publish fails, the
// enrichment worker's poll loop picks up the row within its poll interval.
type NATSSubmitter struct {
	client     *natspkg.Client
	streamName string
	jobSvc     service.EnrichJobService
	logger     *slog.Logger
}

// NewNATSSubmitter creates a NATSSubmitter.
func NewNATSSubmitter(
	client *natspkg.Client,
	streamName string,
	jobSvc service.EnrichJobService,
	logger *slog.Logger,
) *NATSSubmitter {
	return &NATSSubmitter{
		client:     client,
		streamName: streamName,
		jobSvc:     jobSvc,
		logger:     logger,
	}
}

func (s *NATSSubmitter) Name() string { return "enrichment-submitter" }

func (s *NATSSubmitter) Init(bus *event.Bus) error {
	bus.Subscribe(event.SBOMIngested, s.handle)
	return nil
}

func (s *NATSSubmitter) Start(_ context.Context) error { return nil }
func (s *NATSSubmitter) Stop() error                   { return nil }

func (s *NATSSubmitter) handle(ctx context.Context, ev event.Event) {
	d, ok := ev.Data.(event.SBOMIngestedData)
	if !ok {
		return
	}

	if err := s.jobSvc.Enqueue(ctx, d.SBOMID, d.Architecture, d.BuildDate, "all"); err != nil {
		s.logger.Error("enrichment-submitter: enqueue failed",
			"sbom_id", d.SBOMID, "err", err,
		)
		return
	}

	jobID := enrichUUIDToString(d.SBOMID)
	hint, err := json.Marshal(struct {
		ID string `json:"id"`
	}{ID: jobID})
	if err != nil {
		return
	}

	msg := nats.NewMsg(s.streamName + ".enrich.hint")
	msg.Data = hint
	if _, err := s.client.JS.PublishMsgAsync(msg); err != nil {
		s.logger.Warn("enrichment-submitter: hint publish failed; poll loop will pick up",
			"sbom_id", d.SBOMID, "err", err,
		)
	}
}

func enrichUUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
