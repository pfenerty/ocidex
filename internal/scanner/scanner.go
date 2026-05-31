// Package scanner defines the scan request type, the Scanner interface,
// and the lightweight OCI catalog/walker/submitter machinery used by the API.
// The Syft-based scan implementation lives in subpackage engine to keep the
// API binary free of syft and stereoscope when scanning runs out-of-process.
package scanner

import "context"

// Scanner scans an OCI image and returns CycloneDX JSON.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest) ([]byte, error)
}

// ScanRequest identifies an OCI image to scan.
type ScanRequest struct {
	RegistryURL  string // e.g. "zot:5000"
	Insecure     bool
	Repository   string
	Digest       string
	Tag          string // optional, for logging
	Architecture string // e.g. "amd64"; resolved from index entry during catalog walk
	BuildDate    string // org.opencontainers.image.created from manifest annotations
	ImageVersion string // org.opencontainers.image.version from manifest annotations or config labels
	AuthUsername string // registry auth username; empty = anonymous
	AuthToken    string // registry auth token/PAT; empty = no auth
	RegistryID   string // UUID of the source registry; empty = unknown
}
