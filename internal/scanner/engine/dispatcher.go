// Package engine houses the scan + ingest dispatcher used by the scanner-worker.
package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"

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
}

// NewDispatcher creates a Dispatcher backed by the given Syft scanner and SBOM service.
func NewDispatcher(sc scanner.Scanner, sbomSvc service.SBOMService, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{scanner: sc, sbomSvc: sbomSvc, logger: logger}
}

// ProcessOne scans the image described by req and ingests the resulting SBOM.
// Returns the created SBOM id on success.
func (d *Dispatcher) ProcessOne(ctx context.Context, req scanner.ScanRequest) (pgtype.UUID, error) {
	req = scanner.FillMetadata(ctx, req)

	raw, err := d.scanner.Scan(ctx, req)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("scan: %w", err)
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
		RegistryID:   registryID,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("ingest: %w", err)
	}

	d.logger.Info("SBOM ingested from scan", "repo", req.Repository, "digest", req.Digest)
	return sbomID, nil
}
