// Package engine contains the Syft-backed scan implementation and the
// worker-pool dispatcher that drives it. Importing this package transitively
// pulls in github.com/anchore/syft and stereoscope; the lighter API binary
// imports only the parent scanner package and avoids those deps in
// distributed mode.
package engine

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	_ "modernc.org/sqlite" // register "sqlite" driver for Syft RPM DB cataloging

	"github.com/pfenerty/ocidex/internal/scanner"
)

// SyftScanner runs syft against an OCI registry to produce CycloneDX JSON SBOMs.
// It is stateless; registry address and insecure flag are provided per-request.
type SyftScanner struct {
	logger *slog.Logger
}

// NewSyftScanner creates a stateless SyftScanner.
func NewSyftScanner(logger *slog.Logger) *SyftScanner {
	return &SyftScanner{logger: logger}
}

// Scan runs syft against the image identified by req and returns CycloneDX JSON.
func (s *SyftScanner) Scan(ctx context.Context, req scanner.ScanRequest) ([]byte, error) {
	registryHost := normalizeRegistryHost(req.RegistryURL)
	ref := fmt.Sprintf("%s/%s@%s", registryHost, req.Repository, req.Digest)
	s.logger.Info("scanning image", "ref", ref, "tag", req.Tag)

	regOpts := &image.RegistryOptions{InsecureUseHTTP: req.Insecure}
	if req.AuthToken != "" {
		username := req.AuthUsername
		if username == "" {
			username = "ocidex"
		}
		regOpts.Credentials = []image.RegistryCredentials{{
			Authority: registryHost,
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

// normalizeRegistryHost trims any scheme prefix and rewrites docker.io aliases
// to the actual registry hostname syft expects. Mirrors the unexported helper
// in the parent scanner package; duplicated here to keep this subpackage free
// of the catalog HTTP code.
func normalizeRegistryHost(host string) string {
	if i := strings.Index(host, "://"); i != -1 {
		host = strings.TrimSuffix(host[i+3:], "/")
	}
	switch host {
	case "docker.io", "index.docker.io", "hub.docker.com":
		return "registry-1.docker.io"
	}
	return host
}
