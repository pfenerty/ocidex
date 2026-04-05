// Package scanner provides a Syft library wrapper for scanning OCI images.
package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	_ "modernc.org/sqlite" // register "sqlite" driver for Syft RPM DB cataloging
)

// Scanner runs syft against an OCI registry to produce CycloneDX JSON SBOMs.
// It is stateless; registry address and insecure flag are provided per-request.
type Scanner struct {
	logger *slog.Logger
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
}

// NewScanner creates a stateless Scanner.
func NewScanner(logger *slog.Logger) *Scanner {
	return &Scanner{logger: logger}
}

// Scan runs syft against the image identified by req and returns CycloneDX JSON.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) ([]byte, error) {
	ref := fmt.Sprintf("%s/%s@%s", req.RegistryURL, req.Repository, req.Digest)
	s.logger.Info("scanning image", "ref", ref, "tag", req.Tag)

	regOpts := &image.RegistryOptions{InsecureUseHTTP: req.Insecure}
	if req.AuthToken != "" {
		username := req.AuthUsername
		if username == "" {
			username = "ocidex"
		}
		regOpts.Credentials = []image.RegistryCredentials{{
			Authority: req.RegistryURL,
			Username:  username,
			Password:  req.AuthToken,
		}}
	}
	srcCfg := syft.DefaultGetSourceConfig().
		WithSources("oci-registry").
		WithRegistryOptions(regOpts)

	src, err := syft.GetSource(ctx, ref, srcCfg)
	if err != nil {
		return nil, fmt.Errorf("getting source for %s: %w", ref, err)
	}
	defer src.Close()

	result, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("creating SBOM for %s: %w", ref, err)
	}

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("creating encoder: %w", err)
	}

	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *result); err != nil {
		return nil, fmt.Errorf("encoding SBOM for %s: %w", ref, err)
	}

	return buf.Bytes(), nil
}
