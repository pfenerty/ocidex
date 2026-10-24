// Package engine houses the scan + ingest dispatcher used by the scanner-worker.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/jobqueue"
	"github.com/pfenerty/ocidex/internal/netguard"
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
	// egress guards the dispatcher's own registry reads (metadata and size).
	egress netguard.Policy
}

// NewDispatcher creates a Dispatcher backed by the given Syft scanner and SBOM
// service. maxImageBytes rejects images whose manifest advertises more than
// that many compressed layer bytes; pass 0 to scan regardless of size. egress
// guards the registry reads the dispatcher makes before handing off to sc.
func NewDispatcher(sc scanner.Scanner, sbomSvc service.SBOMService, maxImageBytes int64, egress netguard.Policy, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{scanner: sc, sbomSvc: sbomSvc, maxImageBytes: maxImageBytes, egress: egress, logger: logger}
}

// ProcessOne scans the image described by req and ingests the resulting SBOM.
// Returns the created SBOM id on success.
func (d *Dispatcher) ProcessOne(ctx context.Context, req scanner.ScanRequest) (pgtype.UUID, error) {
	req = scanner.FillMetadata(ctx, req, d.egress)

	// Size gate before the pull, not after: syft unpacks every layer, so an
	// image past what this pod's memory limit can hold gets the container
	// OOMKilled rather than returning an error. Nothing is written to the row
	// in that case, so the stuck sweep requeues it and the next attempt kills
	// the worker again — and any scan sharing the pod dies with it. Failing
	// here is permanent because a too-big image is still too big next hour.
	if d.maxImageBytes > 0 {
		size, known, err := scanner.ImageLayerBytes(ctx, req, d.egress)
		if err != nil {
			// A refused address is refused on every retry.
			return pgtype.UUID{}, jobqueue.Permanent(err)
		}
		if known && size > d.maxImageBytes {
			return pgtype.UUID{}, jobqueue.Permanent(fmt.Errorf(
				"image too large to scan: %d compressed layer bytes exceeds SCANNER_MAX_IMAGE_BYTES=%d",
				size, d.maxImageBytes))
		}
	}

	res, err := d.scanner.Scan(ctx, req)
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
	if err := cdx.NewBOMDecoder(bytes.NewReader(res.SBOM), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return pgtype.UUID{}, fmt.Errorf("decode sbom: %w", err)
	}

	version := subjectVersion(req)
	// The SBOM's source is the cluster when the job is attributed to one
	// (ADR-0044 K10), otherwise the registry whose walk found it.
	sourceRef := req.RegistryID
	if req.ClusterID != "" {
		sourceRef = req.ClusterID
	}
	var sourceID pgtype.UUID
	if sourceRef != "" {
		_ = sourceID.Scan(sourceRef) //nolint:errcheck // invalid UUID → zero-value, harmless
	}
	sbomID, err := d.sbomSvc.Ingest(ctx, bom, res.SBOM, service.IngestParams{
		Version:      version,
		Architecture: req.Architecture,
		BuildDate:    req.BuildDate,
		// A registry shares its id with its source row; the namespace it belongs
		// to is a different row whenever the registry was created inside an
		// existing namespace, so Ingest resolves it from the source (ADR-039).
		SourceID:    sourceID,
		IndexDigest: req.IndexDigest,
		GoSymbols:   res.GoSymbols,
	})
	if err != nil {
		err = fmt.Errorf("ingest: %w", err)
		// Ingest refused the SBOM itself, and refuses the same BOM on every
		// retry (ocidex-a7km).
		var verr *service.ValidationError
		if errors.As(err, &verr) {
			return pgtype.UUID{}, jobqueue.Permanent(err)
		}
		return pgtype.UUID{}, err
	}

	d.logger.Info("SBOM ingested from scan", "repo", req.Repository, "digest", req.Digest)
	return sbomID, nil
}

// shortDigestLen is "sha256:" plus 12 hex characters, the length image tooling
// conventionally shortens a digest to.
const shortDigestLen = len("sha256:") + 12

// subjectVersion is the version an SBOM is stored under: the image's version
// label, else the tag it was found by, else its short digest (ocidex-a7km). A
// catalog walk always has a tag, but a running image reported by digest alone
// may have neither, and ingest refuses a container SBOM with no version. The
// index digest is used when there is one, so every platform of a multi-arch
// image shares a version.
func subjectVersion(req scanner.ScanRequest) string {
	switch {
	case req.ImageVersion != "":
		return req.ImageVersion
	case req.Tag != "":
		return req.Tag
	}
	digest := req.IndexDigest
	if digest == "" {
		digest = req.Digest
	}
	if len(digest) > shortDigestLen {
		digest = digest[:shortDigestLen]
	}
	return digest
}
