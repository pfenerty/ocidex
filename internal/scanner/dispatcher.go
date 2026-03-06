package scanner

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/pfenerty/ocidex/internal/service"
)

// Dispatcher manages a worker pool that scans OCI images and ingests the resulting SBOMs.
type Dispatcher struct {
	queue   chan ScanRequest
	scanner *Scanner
	sbomSvc service.SBOMService
	workers int
	logger  *slog.Logger
}

// NewDispatcher creates a Dispatcher with the given scanner, SBOM service, and pool configuration.
func NewDispatcher(sc *Scanner, sbomSvc service.SBOMService, workers, queueSize int, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		queue:   make(chan ScanRequest, queueSize),
		scanner: sc,
		sbomSvc: sbomSvc,
		workers: workers,
		logger:  logger,
	}
}

// Submit enqueues a scan request. Non-blocking; drops and warns if the queue is full.
func (d *Dispatcher) Submit(req ScanRequest) {
	d.SubmitWithResult(req)
}

// SubmitWithResult enqueues a scan request and returns true if accepted, false if queue is full.
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
	close(d.queue)
	wg.Wait()

	d.logger.Info("scanner dispatcher stopped")
}

func (d *Dispatcher) worker(ctx context.Context, id int) {
	d.logger.Debug("scanner worker started", "worker_id", id)
	for req := range d.queue {
		d.process(ctx, req)
	}
}

func (d *Dispatcher) process(ctx context.Context, req ScanRequest) {
	// Fill in missing metadata from the registry manifest/config before scanning.
	// Webhook-triggered requests don't pre-fetch this; the catalog walker does.
	if req.Architecture == "" || req.BuildDate == "" || req.ImageVersion == "" {
		scheme := "https"
		if req.Insecure {
			scheme = "http"
		}
		baseURL := scheme + "://" + req.RegistryURL
		client := &http.Client{}
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
	}

	raw, err := d.scanner.Scan(ctx, req)
	if err != nil {
		d.logger.Error("scan failed", "repo", req.Repository, "digest", req.Digest, "err", err)
		return
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		d.logger.Error("failed to decode SBOM from syft output", "repo", req.Repository, "err", err)
		return
	}

	version := req.Tag
	if req.ImageVersion != "" {
		version = req.ImageVersion
	}
	if _, err := d.sbomSvc.Ingest(ctx, bom, raw, service.IngestParams{
		Version:      version,
		Architecture: req.Architecture,
		BuildDate:    req.BuildDate,
	}); err != nil {
		d.logger.Error("failed to ingest scanned SBOM", "repo", req.Repository, "digest", req.Digest, "err", err)
		return
	}

	d.logger.Info("SBOM ingested from scan", "repo", req.Repository, "digest", req.Digest)
}
