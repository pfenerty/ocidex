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
type Scanner struct {
	registryAddr string
	insecure     bool
	logger       *slog.Logger
}

// ScanRequest identifies an OCI image to scan.
type ScanRequest struct {
	Repository string
	Digest     string
	Tag        string // optional, for logging
}

// NewScanner creates a Scanner using the given registry address and insecure flag.
func NewScanner(registryAddr string, insecure bool, logger *slog.Logger) *Scanner {
	return &Scanner{
		registryAddr: registryAddr,
		insecure:     insecure,
		logger:       logger,
	}
}

// Scan runs syft against the image identified by req and returns CycloneDX JSON.
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) ([]byte, error) {
	ref := fmt.Sprintf("%s/%s@%s", s.registryAddr, req.Repository, req.Digest)
	s.logger.Info("scanning image", "ref", ref, "tag", req.Tag)

	regOpts := &image.RegistryOptions{InsecureUseHTTP: s.insecure}
	srcCfg := syft.DefaultGetSourceConfig().
		WithSources("registry").
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
