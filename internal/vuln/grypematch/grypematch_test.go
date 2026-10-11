package grypematch

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/matryer/is"
)

// component is a CycloneDX component as syft emits it; props carry the syft
// metadata grype reads back (e.g. a Go binary's main module).
type component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Purl       string     `json:"purl,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func cdx(t *testing.T, comps ...component) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func lib(name, ver, purl string, props ...property) component {
	return component{Type: "library", Name: name, Version: ver, Purl: purl, Properties: props}
}

func osComp(name, ver string) component {
	return component{Type: "operating-system", Name: name, Version: ver}
}

// goMainModule marks a component as the main module of a Go binary, the way
// syft's go-module-binary-cataloger records it.
func goMainModule(name, ver string) component {
	return lib(name, ver, "pkg:golang/"+name+"@"+ver,
		property{"syft:package:foundBy", "go-module-binary-cataloger"},
		property{"syft:package:language", "go"},
		property{"syft:package:type", "go-module"},
		property{"syft:package:metadataType", "go-module-buildinfo-entry"},
		property{"syft:metadata:mainModule", name},
	)
}

func ref(id, ns string) vulnerability.Reference {
	return vulnerability.Reference{ID: id, Namespace: ns}
}

func TestMatcherMatch(t *testing.T) {
	medium := &vulnerability.Metadata{
		Severity: "Medium",
		Cvss:     []vulnerability.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}},
	}

	tests := []struct {
		name      string
		vuln      vulnerability.Vulnerability
		doc       []component
		wantFix   string // "" with wantMatch=false means no finding at all
		wantState string
		wantMatch bool
	}{
		{
			name: "pypi affected version reports its fix",
			vuln: vulnerability.Vulnerability{
				Reference: ref("GHSA-9wx4-h78v-vm56", "github:language:python"), PackageName: "requests",
				Constraint: version.MustGetConstraint("< 2.32.0", version.PythonFormat),
				Fix:        vulnerability.Fix{Versions: []string{"2.32.0"}, State: vulnerability.FixStateFixed},
				Metadata:   medium,
			},
			doc:       []component{lib("requests", "2.31.0", "pkg:pypi/requests@2.31.0")},
			wantMatch: true, wantFix: "2.32.0", wantState: "fixed",
		},
		{
			name: "pypi fixed version does not match",
			vuln: vulnerability.Vulnerability{
				Reference: ref("GHSA-9wx4-h78v-vm56", "github:language:python"), PackageName: "requests",
				Constraint: version.MustGetConstraint("< 2.32.0", version.PythonFormat),
				Fix:        vulnerability.Fix{Versions: []string{"2.32.0"}, State: vulnerability.FixStateFixed},
			},
			doc: []component{lib("requests", "2.32.0", "pkg:pypi/requests@2.32.0")},
		},
		{
			// The audit's protobuf case: a record with one fix per release line.
			// The first-listed fix (5.29.6) is below 6.31.1; the fix that clears
			// the install is 6.33.5.
			name: "pypi multi-line record reports the fix on the installed line",
			vuln: vulnerability.Vulnerability{
				Reference: ref("PYSEC-2026-1805", "github:language:python"), PackageName: "protobuf",
				Constraint: version.MustGetConstraint("< 5.29.6 || >= 6.30.0rc1, < 6.33.5", version.PythonFormat),
				Fix:        vulnerability.Fix{Versions: []string{"5.29.6", "6.33.5"}, State: vulnerability.FixStateFixed},
			},
			doc:       []component{lib("protobuf", "6.31.1", "pkg:pypi/protobuf@6.31.1")},
			wantMatch: true, wantFix: "6.33.5", wantState: "fixed",
		},
		{
			// The audit's CoreDNS case: syft records the v1.14.7 binary by its
			// commit pseudo-version, which sorts below every real fix.
			name: "go main module pseudo-version is not compared",
			vuln: vulnerability.Vulnerability{
				Reference: ref("GHSA-63cw-r7xf-jmwr", "github:language:go"), PackageName: "github.com/coredns/coredns",
				Constraint: version.MustGetConstraint("< 1.14.3", version.GolangFormat),
				Fix:        vulnerability.Fix{Versions: []string{"1.14.3"}, State: vulnerability.FixStateFixed},
			},
			doc: []component{goMainModule("github.com/coredns/coredns", "v0.0.0-20260819003913-427fc80ed9ca")},
		},
		{
			// Control for the case above: the same pseudo-version on a dependency
			// (not the main module) IS compared, so the suppression is the main-module
			// rule and not a matcher that never fires.
			name: "go dependency pseudo-version is compared",
			vuln: vulnerability.Vulnerability{
				Reference: ref("GHSA-63cw-r7xf-jmwr", "github:language:go"), PackageName: "github.com/coredns/coredns",
				Constraint: version.MustGetConstraint("< 1.14.3", version.GolangFormat),
				Fix:        vulnerability.Fix{Versions: []string{"1.14.3"}, State: vulnerability.FixStateFixed},
			},
			doc: []component{lib("github.com/coredns/coredns", "v0.0.0-20260819003913-427fc80ed9ca",
				"pkg:golang/github.com/coredns/coredns@v0.0.0-20260819003913-427fc80ed9ca",
				property{"syft:package:language", "go"}, property{"syft:package:type", "go-module"})},
			wantMatch: true, wantFix: "1.14.3", wantState: "fixed",
		},
		{
			// The audit's Grafana case: real release-line ranges, a newer line installed.
			name: "go module on a newer release line does not match",
			vuln: vulnerability.Vulnerability{
				Reference: ref("GHSA-w62r-7c53-fmc5", "github:language:go"), PackageName: "github.com/grafana/grafana",
				Constraint: version.MustGetConstraint(">= 12.0.0, < 12.0.7 || >= 12.1.0, < 12.1.4 || >= 12.2.0, < 12.2.2", version.GolangFormat),
				Fix:        vulnerability.Fix{Versions: []string{"12.0.7", "12.1.4", "12.2.2"}, State: vulnerability.FixStateFixed},
			},
			doc: []component{goMainModule("github.com/grafana/grafana", "v13.2.2")},
		},
		{
			name: "go module on an affected release line matches",
			vuln: vulnerability.Vulnerability{
				Reference: ref("GHSA-w62r-7c53-fmc5", "github:language:go"), PackageName: "github.com/grafana/grafana",
				Constraint: version.MustGetConstraint(">= 12.0.0, < 12.0.7 || >= 12.1.0, < 12.1.4 || >= 12.2.0, < 12.2.2", version.GolangFormat),
				Fix:        vulnerability.Fix{Versions: []string{"12.0.7", "12.1.4", "12.2.2"}, State: vulnerability.FixStateFixed},
			},
			doc:       []component{goMainModule("github.com/grafana/grafana", "v12.1.3")},
			wantMatch: true, wantFix: "12.1.4", wantState: "fixed",
		},
		{
			name: "debian package with no fix is reported wont-fix",
			vuln: vulnerability.Vulnerability{
				Reference: ref("CVE-2022-3715", "debian:distro:debian:11"), PackageName: "bash",
				Constraint: version.MustGetConstraint("< 5.1-2+deb11u2", version.DebFormat),
				Fix:        vulnerability.Fix{State: vulnerability.FixStateWontFix},
			},
			doc: []component{
				osComp("debian", "11"),
				lib("bash", "5.1-2+deb11u1", "pkg:deb/debian/bash@5.1-2%2Bdeb11u1?arch=amd64&distro=debian-11"),
			},
			wantMatch: true, wantState: "wont-fix",
		},
		{
			name: "ubuntu package below the fix is reported fixed",
			vuln: vulnerability.Vulnerability{
				Reference: ref("CVE-2026-54873", "ubuntu:distro:ubuntu:24.04"), PackageName: "openssl",
				Constraint: version.MustGetConstraint("< 3.0.13-0ubuntu3.16", version.DebFormat),
				Fix:        vulnerability.Fix{Versions: []string{"3.0.13-0ubuntu3.16"}, State: vulnerability.FixStateFixed},
			},
			doc: []component{
				osComp("ubuntu", "24.04"),
				lib("openssl", "3.0.13-0ubuntu3.15", "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.15?arch=amd64&distro=ubuntu-24.04"),
			},
			wantMatch: true, wantFix: "3.0.13-0ubuntu3.16", wantState: "fixed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			m := NewMatcher(mock.VulnerabilityProvider(tt.vuln))
			got, err := m.Match(context.Background(), cdx(t, tt.doc...))
			is.NoErr(err)
			if !tt.wantMatch {
				is.Equal(len(got), 0) // no finding
				return
			}
			is.Equal(len(got), 1)
			is.Equal(got[0].VulnerabilityID, tt.vuln.ID)
			is.Equal(got[0].Purl, tt.doc[len(tt.doc)-1].Purl)
			is.Equal(got[0].FixedVersion, tt.wantFix)
			is.Equal(got[0].FixState, tt.wantState)
		})
	}
}

func TestMatcherMatchRelatedMetadata(t *testing.T) {
	is := is.New(t)
	nvd := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID: "CVE-2024-35195", Namespace: "nvd:cpe",
			Internal: vulnerability.Metadata{Severity: "Medium", Description: "from nvd"},
		},
	}
	ghsa := vulnerability.Vulnerability{
		Reference: ref("GHSA-9wx4-h78v-vm56", "github:language:python"), PackageName: "requests",
		Constraint:             version.MustGetConstraint("< 2.32.0", version.PythonFormat),
		RelatedVulnerabilities: []vulnerability.Reference{ref("CVE-2024-35195", "nvd:cpe")},
	}
	got, err := NewMatcher(mock.VulnerabilityProvider(ghsa, nvd)).
		Match(context.Background(), cdx(t, lib("requests", "2.31.0", "pkg:pypi/requests@2.31.0")))
	is.NoErr(err)
	is.Equal(len(got), 1)
	is.Equal(got[0].Related, []string{"CVE-2024-35195"})
	is.Equal(len(got[0].RelatedMetadata), 1)
	is.Equal(got[0].RelatedMetadata[0].Description, "from nvd")
}

func TestMatcherMatchRejectsGarbage(t *testing.T) {
	is := is.New(t)
	_, err := NewMatcher(mock.VulnerabilityProvider()).Match(context.Background(), []byte("not an sbom"))
	is.True(err != nil)
}
