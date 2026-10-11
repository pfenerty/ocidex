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
	Metadata     *vulnerability.Metadata
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

// Match decodes an SBOM document (CycloneDX, SPDX, or syft JSON) and returns
// every vulnerability grype matches against its packages. Findings are sorted by
// purl then vulnerability ID.
func (m *Matcher) Match(ctx context.Context, doc []byte) ([]Finding, error) {
	pkgs, pkgCtx, _, err := grypePkg.ProvideFromReader(bytes.NewReader(doc), grypePkg.ProviderConfig{})
	if err != nil {
		return nil, fmt.Errorf("decoding sbom: %w", err)
	}
	matches, _, err := m.vm.FindMatchesContext(ctx, pkgs, pkgCtx)
	if err != nil {
		return nil, fmt.Errorf("matching: %w", err)
	}
	out := make([]Finding, 0, matches.Count())
	for _, mt := range matches.Sorted() {
		out = append(out, m.toFinding(mt))
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
	if len(v.Fix.Versions) > 0 {
		f.FixedVersion = v.Fix.Versions[0]
	}
	for _, r := range v.RelatedVulnerabilities {
		f.Related = append(f.Related, r.ID)
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
