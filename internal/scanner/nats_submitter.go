package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/service"
)

const (
	natsPublishTimeout = 5 * time.Second

	// ScanHintSubjectSuffix is appended to the stream name for scan job hints.
	// The hint payload is just the scan_jobs row id; the DB row is the source of truth.
	ScanHintSubjectSuffix = ".scan.hint"

	// ScannerHintDurable is the JetStream durable consumer name for scan hints.
	ScannerHintDurable = "scanner-hint"
)

// NATSSubmitter inserts a scan_jobs row and publishes a tiny hint to NATS so
// workers wake up promptly. It satisfies the api.ScanSubmitter interface.
type NATSSubmitter struct {
	client     *natspkg.Client
	streamName string
	jobSvc     service.JobService
	logger     *slog.Logger
}

// NewNATSSubmitter creates a NATSSubmitter backed by the given client.
func NewNATSSubmitter(client *natspkg.Client, streamName string, jobSvc service.JobService) *NATSSubmitter {
	return &NATSSubmitter{
		client:     client,
		streamName: streamName,
		jobSvc:     jobSvc,
		logger:     slog.Default(),
	}
}

// scanHint is the entire wire payload: just the row id. Auth credentials and
// scan parameters live on scan_jobs + registry rows; the worker reads them
// during ClaimByID.
type scanHint struct {
	ID string `json:"id"`
}

// Submit inserts a scan_jobs row in the queued state, then best-effort publishes
// a NATS hint. If publish fails, the worker poll loop will pick the row up. If
// a row with the same (registry_id, digest) already exists (unique violation on
// nats_msg_id), Submit returns nil — the existing row is already being
// processed by some worker.
func (s *NATSSubmitter) Submit(ctx context.Context, req ScanRequest) error {
	// nats_msg_id doubles as a row-level idempotency key so re-enqueues for the
	// same registry+digest pair collapse to one row. The column name is a
	// historical artifact from the dual-write era; the value still serves the
	// same purpose at the row level.
	idempotencyKey := req.RegistryID + "@" + req.Digest

	job, err := s.jobSvc.Enqueue(ctx, req.RegistryID, req.Repository, req.Digest, req.Tag, idempotencyKey)
	if err != nil {
		if isUniqueViolation(err) {
			// Already enqueued; the existing row is being polled or hinted. No-op.
			return nil
		}
		return err
	}

	hint, err := json.Marshal(scanHint{ID: job.ID})
	if err != nil {
		return err
	}

	pubCtx, cancel := context.WithTimeout(ctx, natsPublishTimeout)
	defer cancel()

	if _, err := s.client.JS.Publish(pubCtx, s.streamName+ScanHintSubjectSuffix, hint); err != nil {
		// Hint is best-effort — the row exists in the DB, the worker poll loop
		// will pick it up within the poll interval.
		s.logger.Warn("scan hint publish failed; poll loop will pick up", "job_id", job.ID, "err", err)
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ScanRequestFromClaim converts a ScanJobClaim into a ScanRequest for the processor.
func ScanRequestFromClaim(c service.ScanJobClaim) ScanRequest {
	return ScanRequest{
		RegistryURL:  c.RegistryURL,
		Insecure:     c.Insecure,
		Repository:   c.Repository,
		Digest:       c.Digest,
		Tag:          c.Tag,
		AuthUsername: c.AuthUsername,
		AuthToken:    c.AuthToken,
		RegistryID:   c.RegistryID,
	}
}
