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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	syftpkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"

	// Registers the "sqlite" driver Syft's RPM DB cataloger opens. glebarez/go-sqlite, not
	// modernc.org/sqlite: grype's database layer links glebarez, and both register the
	// name "sqlite", so a binary linking the two panics at init (ADR-049).
	_ "github.com/glebarez/go-sqlite"

	"github.com/pfenerty/ocidex/internal/gosymbols"
	"github.com/pfenerty/ocidex/internal/scanner"
)

// SyftScanner runs syft against an OCI registry to produce CycloneDX JSON SBOMs.
// It is stateless; registry address and insecure flag are provided per-request.
type SyftScanner struct {
	logger  *slog.Logger
	symbols cataloging.SymbolScope
}

// NewSyftScanner creates a stateless SyftScanner. symbolScope selects which Go
// binary packages get their linked function symbols captured ("none", "stdlib",
// "extended-stdlib", "all"); they ride in the CycloneDX output as ocidex
// properties so vulnerability matching can filter by linked symbols (ADR-050).
func NewSyftScanner(logger *slog.Logger, symbolScope string) *SyftScanner {
	scope := cataloging.SymbolScope(symbolScope)
	if scope == "" {
		scope = cataloging.SymbolScopeNone
	}
	return &SyftScanner{logger: logger, symbols: scope}
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

	cfg := syft.DefaultCreateSBOMConfig()
	cfg.Packages = cfg.Packages.WithGolangConfig(cfg.Packages.Golang.WithCaptureSymbols(s.symbols))
	result, err := syft.CreateSBOM(ctx, src, cfg)
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

	out, err := addGoSymbols(buf.Bytes(), result)
	if err != nil {
		return nil, fmt.Errorf("adding go symbols for %s: %w", ref, err)
	}
	return out, nil
}

// addGoSymbols carries the function symbols syft captured for Go binary packages
// into the CycloneDX document, which syft's encoder drops (ADR-050). Each
// component is found by the syft package ID embedded in its bom-ref. The document
// passes through unchanged when no package has symbols.
func addGoSymbols(doc []byte, result *sbom.SBOM) ([]byte, error) {
	byID := map[string]gosymbols.Table{}
	for p := range result.Artifacts.Packages.Enumerate() {
		if m, ok := p.Metadata.(syftpkg.GolangBinaryBuildinfoEntry); ok && len(m.Symbols) > 0 {
			byID[string(p.ID())] = m.Symbols
		}
	}
	if len(byID) == 0 {
		return doc, nil
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(doc), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}
	attachSymbols(bom.Components, byID)
	var buf bytes.Buffer
	if err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(&bom); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func attachSymbols(comps *[]cdx.Component, byID map[string]gosymbols.Table) {
	if comps == nil {
		return
	}
	for i := range *comps {
		c := &(*comps)[i]
		if t, ok := byID[syftPackageID(c.BOMRef)]; ok {
			props := append(propertiesOf(c), gosymbols.Properties(t)...)
			c.Properties = &props
		}
		attachSymbols(c.Components, byID)
	}
}

func propertiesOf(c *cdx.Component) []cdx.Property {
	if c.Properties == nil {
		return nil
	}
	return *c.Properties
}

// syftPackageID extracts the syft package ID from a bom-ref syft wrote: either
// "<purl>?package-id=<id>" (or "&package-id=" after qualifiers) or the bare ID.
func syftPackageID(bomRef string) string {
	if i := strings.LastIndex(bomRef, "package-id="); i >= 0 {
		return bomRef[i+len("package-id="):]
	}
	return bomRef
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
