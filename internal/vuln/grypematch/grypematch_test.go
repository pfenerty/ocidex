package grypematch

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/matryer/is"
)

func cdxDoc(purls ...string) []byte {
	comps := ""
	for i, p := range purls {
		if i > 0 {
			comps += ","
		}
		comps += fmt.Sprintf(`{"bom-ref":"c%d","type":"library","name":"requests","version":"%s","purl":%q}`,
			i, strings.SplitN(p, "@", 2)[1], p)
	}
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` + comps + `]}`)
}

func TestMatcherMatch(t *testing.T) {
	affected := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-9wx4-h78v-vm56",
			Namespace: "github:language:python",
		},
		Metadata: &vulnerability.Metadata{
			Severity: "Medium",
			Cvss:     []vulnerability.Cvss{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}},
		},
		PackageName:            "requests",
		Constraint:             version.MustGetConstraint("< 2.32.0", version.PythonFormat),
		Fix:                    vulnerability.Fix{Versions: []string{"2.32.0"}, State: vulnerability.FixStateFixed},
		RelatedVulnerabilities: []vulnerability.Reference{{ID: "CVE-2024-35195", Namespace: "nvd:cpe"}},
	}

	tests := []struct {
		name string
		purl string
		want int
	}{
		{"affected version matches", "pkg:pypi/requests@2.31.0", 1},
		{"fixed version does not", "pkg:pypi/requests@2.32.0", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			m := NewMatcher(mock.VulnerabilityProvider(affected))
			got, err := m.Match(context.Background(), cdxDoc(tt.purl))
			is.NoErr(err)
			is.Equal(len(got), tt.want)
			if tt.want == 0 {
				return
			}
			f := got[0]
			is.Equal(f.Purl, tt.purl)
			is.Equal(f.VulnerabilityID, "GHSA-9wx4-h78v-vm56")
			is.Equal(f.FixState, "fixed")
			is.Equal(f.FixedVersion, "2.32.0")
			is.Equal(f.Related, []string{"CVE-2024-35195"})
			is.True(f.Metadata != nil)
			is.Equal(f.Metadata.Severity, "Medium")
		})
	}
}

func TestMatcherMatchRejectsGarbage(t *testing.T) {
	is := is.New(t)
	_, err := NewMatcher(mock.VulnerabilityProvider()).Match(context.Background(), []byte("not an sbom"))
	is.True(err != nil)
}
