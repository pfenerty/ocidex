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
	"net/http"
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
	"github.com/pfenerty/ocidex/internal/netguard"
	"github.com/pfenerty/ocidex/internal/scanner"
)

// GuardDefaultTransport makes every connection http.DefaultTransport opens — and
// every clone of it made afterwards — obey p.
//
// This is how syft's registry pulls are guarded (ocidex-avsz.7). Syft takes no
// transport: stereoscope's RegistryOptions has no hook, and its registry
// provider builds one per pull from http.DefaultTransport.(*http.Transport).Clone()
// (stereoscope pkg/image/oci/registry_provider.go getTransport), not from
// go-containerregistry's remote.DefaultTransport. Clone copies DialContext, so
// replacing it here puts the check on the resolved IP of every pull connection,
// redirects and DNS rebinding included.
//
// It mutates process-global state, so only the scanner-worker main calls it,
// once, at startup. Everything else in that process that uses the default
// transport is held to the same policy, which is intended: none of it should
// reach a private address on a user's say-so. The residual risk is a future
// stereoscope that stops cloning the default transport; TestScanEgressDenied
// fails if it does.
func GuardDefaultTransport(p netguard.Policy) {
	http.DefaultTransport.(*http.Transport).DialContext = p.DialContext
}

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

// Scan runs syft against the image identified by req and returns the CycloneDX
// document plus the Go symbols syft captured, keyed by bom-ref.
func (s *SyftScanner) Scan(ctx context.Context, req scanner.ScanRequest) (scanner.Result, error) {
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
		return scanner.Result{}, fmt.Errorf("getting source for %s: %w", ref, err)
	}
	defer src.Close()

	cfg := syft.DefaultCreateSBOMConfig()
	cfg.Packages = cfg.Packages.WithGolangConfig(cfg.Packages.Golang.WithCaptureSymbols(s.symbols))
	result, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return scanner.Result{}, fmt.Errorf("creating SBOM for %s: %w", ref, err)
	}

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return scanner.Result{}, fmt.Errorf("creating encoder: %w", err)
	}

	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *result); err != nil {
		return scanner.Result{}, fmt.Errorf("encoding SBOM for %s: %w", ref, err)
	}

	syms, err := goSymbolsByBOMRef(buf.Bytes(), result)
	if err != nil {
		return scanner.Result{}, fmt.Errorf("collecting go symbols for %s: %w", ref, err)
	}
	return scanner.Result{SBOM: buf.Bytes(), GoSymbols: syms}, nil
}

// goSymbolsByBOMRef collects the function symbols syft captured for Go binary
// packages, keyed by the bom-ref each package got in the encoded document.
// syft's CycloneDX encoder has no field for them (ADR-050), so they travel to
// ingest beside the document. The document is only decoded when some package
// has symbols.
func goSymbolsByBOMRef(doc []byte, result *sbom.SBOM) (map[string]gosymbols.Table, error) {
	byID := map[string]gosymbols.Table{}
	for p := range result.Artifacts.Packages.Enumerate() {
		if m, ok := p.Metadata.(syftpkg.GolangBinaryBuildinfoEntry); ok && len(m.Symbols) > 0 {
			byID[string(p.ID())] = m.Symbols
		}
	}
	if len(byID) == 0 {
		return nil, nil
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(doc), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}
	out := map[string]gosymbols.Table{}
	var walk func(comps *[]cdx.Component)
	walk = func(comps *[]cdx.Component) {
		if comps == nil {
			return
		}
		for _, c := range *comps {
			if t, ok := byID[syftPackageID(c.BOMRef)]; ok && c.BOMRef != "" {
				out[c.BOMRef] = t
			}
			walk(c.Components)
		}
	}
	walk(bom.Components)
	return out, nil
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
