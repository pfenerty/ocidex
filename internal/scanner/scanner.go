// Package scanner defines the scan request type, the Scanner interface,
// and the lightweight OCI catalog/walker/submitter machinery used by the API.
// The Syft-based scan implementation lives in subpackage engine to keep the
// API binary free of syft and stereoscope when scanning runs out-of-process.
package scanner

import (
	"context"

	"github.com/pfenerty/ocidex/internal/gosymbols"
)

// Scanner scans an OCI image.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest) (Result, error)
}

// Result is what a scan produces: the SBOM as CycloneDX JSON, plus data the
// scanner holds that CycloneDX has no field for, handed to ingest directly
// rather than smuggled through the document.
type Result struct {
	// SBOM is the CycloneDX JSON document.
	SBOM []byte
	// GoSymbols maps a component's bom-ref to the function symbols linked into
	// the Go binary it was read from (ADR-050); nil when none were captured.
	GoSymbols map[string]gosymbols.Table
}

// ScanRequest identifies an OCI image to scan.
type ScanRequest struct {
	RegistryURL  string // e.g. "zot:5000"
	Insecure     bool
	Repository   string
	Digest       string
	IndexDigest  string // multi-arch index this child was expanded from; empty for single-arch
	Tag          string // optional, for logging
	Architecture string // e.g. "amd64"; resolved from index entry during catalog walk
	BuildDate    string // org.opencontainers.image.created from manifest annotations
	ImageVersion string // org.opencontainers.image.version from manifest annotations or config labels
	AuthUsername string // registry auth username; empty = anonymous
	AuthToken    string // registry auth token/PAT; empty = no auth
	RegistryID   string // UUID of the source registry; empty = unknown
}
