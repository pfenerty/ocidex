// Package engine houses the scan + ingest dispatcher used by the scanner-worker.
package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/jobqueue"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// Dispatcher runs a single scan: fetch image, decode SBOM, ingest. It does not
// touch the scan_jobs lifecycle — the caller (NATS hint handler or DB poll loop)
// owns Claim / Finish / Fail. This keeps the job state machine in one place.
type Dispatcher struct {
	scanner scanner.Scanner
	sbomSvc service.SBOMService
	logger  *slog.Logger
	// maxImageBytes is the compressed-layer ceiling above which an image is
	// rejected without being pulled. 0 disables the check.
	maxImageBytes int64
}

// NewDispatcher creates a Dispatcher backed by the given Syft scanner and SBOM
// service. maxImageBytes rejects images whose manifest advertises more than
// that many compressed layer bytes; pass 0 to scan regardless of size.
func NewDispatcher(sc scanner.Scanner, sbomSvc service.SBOMService, maxImageBytes int64, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{scanner: sc, sbomSvc: sbomSvc, maxImageBytes: maxImageBytes, logger: logger}
}

// ProcessOne scans the image described by req and ingests the resulting SBOM.
// Returns the created SBOM id on success.
func (d *Dispatcher) ProcessOne(ctx context.Context, req scanner.ScanRequest) (pgtype.UUID, error) {
	req = scanner.FillMetadata(ctx, req)

	// Size gate before the pull, not after: syft unpacks every layer, so an
	// image past what this pod's memory limit can hold gets the container
	// OOMKilled rather than returning an error. Nothing is written to the row
	// in that case, so the stuck sweep requeues it and the next attempt kills
	// the worker again — and any scan sharing the pod dies with it. Failing
	// here is permanent because a too-big image is still too big next hour.
	if d.maxImageBytes > 0 {
		if size, known := scanner.ImageLayerBytes(ctx, req); known && size > d.maxImageBytes {
			return pgtype.UUID{}, jobqueue.Permanent(fmt.Errorf(
				"image too large to scan: %d compressed layer bytes exceeds SCANNER_MAX_IMAGE_BYTES=%d",
				size, d.maxImageBytes))
		}
	}

	raw, err := d.scanner.Scan(ctx, req)
	if err != nil {
		err = fmt.Errorf("scan: %w", err)
		// Single chokepoint for both the NATS hint path and the DB poll loop, so
		// the classification applies wherever the scan was triggered from.
		if isPermanentScanError(err) {
			return pgtype.UUID{}, jobqueue.Permanent(err)
		}
		return pgtype.UUID{}, err
	}

	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return pgtype.UUID{}, fmt.Errorf("decode sbom: %w", err)
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
		// A registry shares its id with its source row; the namespace it belongs
		// to is a different row whenever the registry was created inside an
		// existing namespace, so Ingest resolves it from the source (ADR-039).
		SourceID:    registryID,
		IndexDigest: req.IndexDigest,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("ingest: %w", err)
	}

	d.logger.Info("SBOM ingested from scan", "repo", req.Repository, "digest", req.Digest)
	return sbomID, nil
}
