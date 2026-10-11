// Package grypematch matches SBOM documents against the grype vulnerability
// database (ADR-049). It is its own package so that only the binaries that match
// (vuln-worker, vuln-parity) link grype and its SQLite database stack.
package grypematch

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/stock"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"

	"github.com/pfenerty/ocidex/internal/gosymbols"
	"github.com/pfenerty/ocidex/internal/vuln"
)

// Finding is one (component purl → vulnerability) match produced by grype.
type Finding struct {
	Purl            string
	VulnerabilityID string
	// Namespace is the grype data source the match came from, e.g.
	// "debian:distro:debian:12" or "github:language:go".
	Namespace string
	// Related holds the IDs of records describing the same issue (the CVE behind
	// a GHSA, the NVD record behind a distro advisory).
	Related      []string
	FixState     string
	FixedVersion string
	// GoSymbolSetID is the symbol set the match was made against (0: module level).
	GoSymbolSetID int64
	Metadata      *vulnerability.Metadata
	// RelatedMetadata is the metadata of each Related record that has any; NVD's
	// CVSS usually arrives this way for distro advisories.
	RelatedMetadata []*vulnerability.Metadata
}

// Matcher matches SBOM documents against a loaded grype vulnerability database.
// It replaces the OSV query API: grype's matchers own version comparison per
// ecosystem, distro fix states, Go main-module pseudo-version handling, and
// source-package (upstream) matching.
type Matcher struct {
	provider vulnerability.Provider
	vm       *grype.VulnerabilityMatcher
}

// NewMatcher wraps a vulnerability provider with grype's default matchers,
// configured as the grype CLI configures them by default: CPE matching only for
// packages no ecosystem matcher understands, and main-module pseudo-versions never
// compared.
func NewMatcher(provider vulnerability.Provider) *Matcher {
	cfg := matcher.Config{
		Stock: stock.MatcherConfig{UseCPEs: true},
		Dpkg:  dpkg.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto},
		Rpm:   rpm.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto},
	}
	return &Matcher{
		provider: provider,
		vm: &grype.VulnerabilityMatcher{
			VulnerabilityProvider: provider,
			Matchers:              matcher.NewDefaultMatchers(cfg),
		},
	}
}

// Symbols maps a Go binary package (purl and binary path) to the stored symbol
// set it links (ADR-050).
type Symbols map[vuln.GoSymbolKey]vuln.GoSymbolSet

// Match decodes an SBOM document (CycloneDX, SPDX, or syft JSON) and returns
// every vulnerability grype matches against its packages. Go binary packages
// found in syms are matched at symbol level: a govulndb advisory whose
// vulnerable symbols are not linked is dropped. Packages without symbols are
// matched at module level. Findings are sorted by purl then vulnerability ID.
func (m *Matcher) Match(ctx context.Context, doc []byte, syms Symbols) ([]Finding, error) {
	pkgs, pkgCtx, _, err := grypePkg.ProvideFromReader(bytes.NewReader(doc), grypePkg.ProviderConfig{})
	if err != nil {
		return nil, fmt.Errorf("decoding sbom: %w", err)
	}
	setOf := attachSymbols(pkgs, syms)
	matches, _, err := m.vm.FindMatchesContext(ctx, pkgs, pkgCtx)
	if err != nil {
		return nil, fmt.Errorf("matching: %w", err)
	}
	out := make([]Finding, 0, matches.Count())
	for _, mt := range matches.Sorted() {
		f := m.toFinding(mt)
		f.GoSymbolSetID = setOf[mt.Package.ID]
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Purl != out[j].Purl {
			return out[i].Purl < out[j].Purl
		}
		return out[i].VulnerabilityID < out[j].VulnerabilityID
	})
	return out, nil
}

func (m *Matcher) toFinding(mt match.Match) Finding {
	v := mt.Vulnerability
	f := Finding{
		Purl:            mt.Package.PURL,
		VulnerabilityID: v.ID,
		Namespace:       v.Namespace,
		FixState:        string(v.Fix.State),
		Metadata:        v.Metadata,
	}
	f.FixedVersion = suggestedFix(mt.Package, v.Fix.Versions)
	for _, r := range v.RelatedVulnerabilities {
		f.Related = append(f.Related, r.ID)
		// grype's own presenter resolves related records the same way.
		md, err := m.provider.VulnerabilityMetadata(r) //nolint:staticcheck // no non-deprecated way to read a related record's metadata
		if err == nil && md != nil {
			f.RelatedMetadata = append(f.RelatedMetadata, md)
		}
	}
	return f
}

// Close releases the underlying database.
func (m *Matcher) Close() error { return m.provider.Close() }

// DBConfig locates and validates the grype vulnerability database.
type DBConfig struct {
	// RootDir is where the database is installed (a persistent volume in-cluster).
	RootDir string
	// UpdateURL is the listing grype checks for newer databases.
	UpdateURL string
	// MaxAge rejects a database built longer ago than this.
	MaxAge time.Duration
}

// LoadDB installs or updates the grype database under cfg.RootDir (when update is
// true) and opens it. Download, checksum validation, and the atomic swap into
// place are grype's own (its installation curator).
func LoadDB(cfg DBConfig, update bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	id := clio.Identification{Name: "ocidex-vuln-worker"}
	dist := v6dist.DefaultConfig()
	dist.ID = id
	if cfg.UpdateURL != "" {
		dist.LatestURL = cfg.UpdateURL
	}
	inst := v6inst.DefaultConfig(id)
	inst.DBRootDir = cfg.RootDir
	if cfg.MaxAge > 0 {
		inst.MaxAllowedBuiltAge = cfg.MaxAge
	}
	// The worker decides when to check; don't let grype's own throttle skip it.
	inst.UpdateCheckMaxFrequency = 0
	return grype.LoadVulnerabilityDB(dist, inst, update)
}

// suggestedFix picks, from a record's fixed versions, the lowest one above the
// installed version — the upgrade that clears this match. A record spanning
// several release lines lists one fix per line ("5.29.6", "6.33.5"); the first
// is wrong for an install on the later line. This is the rule grype's own
// presenter applies (calculateSuggestedFixedVersion, unexported), on grype's
// per-ecosystem comparators.
func suggestedFix(p grypePkg.Package, fixes []string) string {
	if len(fixes) <= 1 {
		if len(fixes) == 1 {
			return fixes[0]
		}
		return ""
	}
	format := grypePkg.VersionFormat(p)
	installed := version.New(p.Version, format)
	var best *version.Version
	for _, raw := range fixes {
		v := version.New(raw, format)
		if above, err := v.Is(version.GT, installed); err != nil || !above {
			continue
		}
		if best == nil {
			best = v
			continue
		}
		if lower, err := v.Is(version.LT, best); err == nil && lower {
			best = v
		}
	}
	if best == nil {
		return fixes[0]
	}
	return best.Raw
}

// attachSymbols sets the linked symbols on each Go binary package syms knows and
// returns which symbol set each such package got. grype's gosymbols qualifier
// reads GolangBinMetadata.Symbols and expects names already normalized to
// govulndb's convention, which is how they are stored.
func attachSymbols(pkgs []grypePkg.Package, syms Symbols) map[grypePkg.ID]int64 {
	if len(syms) == 0 {
		return nil
	}
	setOf := map[grypePkg.ID]int64{}
	for i := range pkgs {
		md, ok := pkgs[i].Metadata.(grypePkg.GolangBinMetadata)
		if !ok {
			continue
		}
		for _, loc := range pkgs[i].Locations.ToSlice() {
			if set, ok := syms[vuln.GoSymbolKey{Purl: pkgs[i].PURL, FilePath: loc.RealPath}]; ok {
				md.Symbols = set.Symbols
				pkgs[i].Metadata = md
				setOf[pkgs[i].ID] = set.ID
				break
			}
		}
	}
	return setOf
}

// SymbolsFromDocument reads the ocidex Go symbol properties (ADR-050) carried by
// a CycloneDX document's components, normalized — the form a scanner-produced
// document has before ingest moves them into the database. Anything that is not
// CycloneDX JSON yields nil.
func SymbolsFromDocument(doc []byte) Symbols {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(doc), cdx.BOMFileFormatJSON).Decode(&bom); err != nil || bom.Components == nil {
		return nil
	}
	out := Symbols{}
	var walk func(comps []cdx.Component)
	walk = func(comps []cdx.Component) {
		for _, c := range comps {
			if c.Properties != nil && c.PackageURL != "" {
				if t, _ := gosymbols.FromProperties(*c.Properties); t != nil {
					path := ""
					for _, p := range *c.Properties {
						if p.Name == "syft:location:0:path" {
							path = p.Value
						}
					}
					out[vuln.GoSymbolKey{Purl: c.PackageURL, FilePath: path}] = vuln.GoSymbolSet{Symbols: gosymbols.Normalized(t)}
				}
			}
			if c.Components != nil {
				walk(*c.Components)
			}
		}
	}
	walk(*bom.Components)
	if len(out) == 0 {
		return nil
	}
	return out
}
