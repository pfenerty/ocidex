package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/service"
)

// Dispatcher manages a worker pool that scans OCI images and ingests the resulting SBOMs.
type Dispatcher struct {
	queue    chan ScanRequest
	stopping chan struct{} // closed by Run when shutdown begins
	scanner  Scanner
	sbomSvc  service.SBOMService
	jobSvc   service.JobService // optional; nil disables job tracking
	workers  int
	logger   *slog.Logger
}

// NewDispatcher creates a Dispatcher with the given scanner, SBOM service, and pool configuration.
func NewDispatcher(sc Scanner, sbomSvc service.SBOMService, workers, queueSize int, logger *slog.Logger, jobSvc service.JobService) *Dispatcher {
	return &Dispatcher{
		queue:    make(chan ScanRequest, queueSize),
		stopping: make(chan struct{}),
		scanner:  sc,
		sbomSvc:  sbomSvc,
		jobSvc:   jobSvc,
		workers:  workers,
		logger:   logger,
	}
}

// Submit enqueues a scan request. Blocks until a slot is available or the dispatcher stops.
func (d *Dispatcher) Submit(ctx context.Context, req ScanRequest) error {
	if d.jobSvc != nil {
		if req.MsgID == "" {
			req.MsgID = req.RegistryID + "@" + req.Digest
		}
		if _, err := d.jobSvc.Enqueue(ctx, req.RegistryID, req.Repository, req.Digest, req.Tag, req.MsgID); err != nil {
			d.logger.Warn("scan_jobs: failed to enqueue job", "msg_id", req.MsgID, "err", err)
		}
	}
	select {
	case d.queue <- req:
		d.logger.Debug("scan queued", "repo", req.Repository, "digest", req.Digest)
		return nil
	case <-d.stopping:
		return fmt.Errorf("dispatcher stopping")
	}
}

// SubmitWithResult enqueues a scan request without blocking. Returns true if accepted, false if the queue is full.
func (d *Dispatcher) SubmitWithResult(req ScanRequest) bool {
	select {
	case d.queue <- req:
		d.logger.Debug("scan queued", "repo", req.Repository, "digest", req.Digest)
		return true
	default:
		d.logger.Warn("scan queue full, dropping request", "repo", req.Repository, "digest", req.Digest)
		return false
	}
}

// Run starts the worker goroutines and blocks until ctx is cancelled.
// Workers drain the queue before returning.
func (d *Dispatcher) Run(ctx context.Context) {
	d.logger.Info("scanner dispatcher starting", "workers", d.workers)

	var wg sync.WaitGroup
	for i := range d.workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d.worker(ctx, id)
		}(i)
	}

	<-ctx.Done()
	close(d.stopping) // unblock any Submit calls waiting for a slot
	close(d.queue)    // signal workers to drain and exit
	wg.Wait()

	d.logger.Info("scanner dispatcher stopped")
}

func (d *Dispatcher) worker(ctx context.Context, id int) {
	d.logger.Debug("scanner worker started", "worker_id", id)
	for req := range d.queue {
		if err := d.startJob(ctx, req.MsgID); err != nil {
			d.logger.Warn("scan_jobs: failed to mark job running", "msg_id", req.MsgID, "err", err)
		}
		_ = d.process(ctx, req)
	}
}

// ProcessOne processes a single scan request synchronously and returns any error.
// Used by NATSExtension to defer Ack/Nak to after processing completes.
func (d *Dispatcher) ProcessOne(ctx context.Context, req ScanRequest) error {
	return d.process(ctx, req)
}

func (d *Dispatcher) process(ctx context.Context, req ScanRequest) error {
	// Fill in missing metadata from the registry manifest/config before scanning.
	// Webhook-triggered requests don't pre-fetch this; the catalog walker does.
	if req.Architecture == "" || req.BuildDate == "" || req.ImageVersion == "" {
		req = d.fillMetadata(ctx, req)
	}

	raw, err := d.scanner.Scan(ctx, req)
	if err != nil {
		d.logger.Error("scan failed", "repo", req.Repository, "digest", req.Digest, "err", err)
		if ferr := d.failJob(ctx, req.MsgID, err.Error()); ferr != nil {
			d.logger.Warn("scan_jobs: failed to mark job failed", "msg_id", req.MsgID, "err", ferr)
		}
		return err
	}

	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		d.logger.Error("failed to decode SBOM from syft output", "repo", req.Repository, "err", err)
		if ferr := d.failJob(ctx, req.MsgID, err.Error()); ferr != nil {
			d.logger.Warn("scan_jobs: failed to mark job failed", "msg_id", req.MsgID, "err", ferr)
		}
		return err
	}

	version := req.Tag
	if req.ImageVersion != "" {
		version = req.ImageVersion
	}
	var registryID pgtype.UUID
	if req.RegistryID != "" {
		_ = registryID.Scan(req.RegistryID) //nolint:errcheck // invalid UUID → zero-value, harmless
	}
	sbomID, err := d.sbomSvc.Ingest(ctx, bom, raw, service.IngestParams{
		Version:      version,
		Architecture: req.Architecture,
		BuildDate:    req.BuildDate,
		RegistryID:   registryID,
	})
	if err != nil {
		d.logger.Error("failed to ingest scanned SBOM", "repo", req.Repository, "digest", req.Digest, "err", err)
		if ferr := d.failJob(ctx, req.MsgID, err.Error()); ferr != nil {
			d.logger.Warn("scan_jobs: failed to mark job failed", "msg_id", req.MsgID, "err", ferr)
		}
		return err
	}

	d.logger.Info("SBOM ingested from scan", "repo", req.Repository, "digest", req.Digest)
	if err := d.finishJob(ctx, req.MsgID, sbomID); err != nil {
		d.logger.Error("scan_jobs: failed to mark job succeeded", "msg_id", req.MsgID, "err", err)
		return err
	}
	return nil
}

func (d *Dispatcher) fillMetadata(ctx context.Context, req ScanRequest) ScanRequest {
	scheme := "https"
	if req.Insecure {
		scheme = "http"
	}
	baseURL := scheme + "://" + normalizeRegistryHost(req.RegistryURL)
	client := &http.Client{Transport: newOCITokenTransport(req.AuthUsername, req.AuthToken)}
	meta := ociGetImageMetadata(ctx, client, baseURL, req.Repository, req.Digest)
	if req.Architecture == "" {
		req.Architecture = meta.architecture
	}
	if req.BuildDate == "" {
		req.BuildDate = meta.buildDate
	}
	if req.ImageVersion == "" {
		req.ImageVersion = meta.imageVersion
	}
	return req
}

func (d *Dispatcher) startJob(ctx context.Context, msgID string) error {
	if d.jobSvc == nil || msgID == "" {
		return nil
	}
	return d.jobSvc.Start(ctx, msgID)
}

func (d *Dispatcher) failJob(ctx context.Context, msgID, errMsg string) error {
	if d.jobSvc == nil || msgID == "" {
		return nil
	}
	return d.jobSvc.Fail(ctx, msgID, errMsg)
}

func (d *Dispatcher) finishJob(ctx context.Context, msgID string, sbomID pgtype.UUID) error {
	if d.jobSvc == nil || msgID == "" {
		return nil
	}
	return d.jobSvc.Finish(ctx, msgID, sbomID)
}
