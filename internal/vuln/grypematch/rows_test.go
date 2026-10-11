package grypematch

import (
	"strings"
	"testing"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/vuln"
)

func md(ns, id, sev, desc string, vectors ...string) *vulnerability.Metadata {
	m := &vulnerability.Metadata{ID: id, Namespace: ns, Severity: sev, Description: desc}
	for _, v := range vectors {
		m.Cvss = append(m.Cvss, vulnerability.Cvss{Version: "3.1", Vector: v})
	}
	return m
}

const (
	critVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" // 10.0
	medVector  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N" // 5.3
)

func TestRows(t *testing.T) {
	t.Run("one row per ID; the matched sources' own severity beats NVD's", func(t *testing.T) {
		is := is.New(t)
		rows := Rows([]Finding{
			{
				Purl: "pkg:deb/debian/expat@2.5.0-1?distro=debian-12", VulnerabilityID: "CVE-2024-45490",
				Metadata: md("debian:distro:debian:12", "CVE-2024-45490", "Negligible", "debian text"),
				Related:  []string{"CVE-2024-45490"},
				RelatedMetadata: []*vulnerability.Metadata{
					md("nvd:cpe", "CVE-2024-45490", "Critical", "nvd text", critVector),
				},
			},
			{
				Purl: "pkg:deb/ubuntu/expat@2.6.1-2?distro=ubuntu-24.04", VulnerabilityID: "CVE-2024-45490",
				Metadata: md("ubuntu:distro:ubuntu:24.04", "CVE-2024-45490", "Medium", "ubuntu text", medVector),
			},
		})
		is.Equal(len(rows), 1)
		r := rows[0]
		is.Equal(r.ID, "CVE-2024-45490")
		is.Equal(r.CanonicalID, "CVE-2024-45490")
		is.Equal(r.Severity, vuln.SeverityMedium) // max(Debian Negligible, Ubuntu Medium), not NVD Critical
		is.True(r.CVSSScore != nil && *r.CVSSScore == 5.3)
		is.Equal(r.CVSSVector, medVector)  // a matched record's own CVSS is preferred for display
		is.Equal(len(r.Aliases), 0)        // the self-reference is not an alias
		is.Equal(r.Details, "debian text") // the matched record's own text beats a related one
		is.True(len(r.Raw) > 0)
	})

	t.Run("a related record's CVSS decides only when no matched source has a view", func(t *testing.T) {
		is := is.New(t)
		rows := Rows([]Finding{{
			Purl: "pkg:golang/stdlib@1.18.2", VulnerabilityID: "GO-2023-1703",
			Metadata:        md("govulndb:language:go", "GO-2023-1703", "", "html/template"),
			Related:         []string{"CVE-2023-24538"},
			RelatedMetadata: []*vulnerability.Metadata{md("nvd:cpe", "CVE-2023-24538", "Critical", "", critVector)},
		}})
		is.Equal(rows[0].Severity, vuln.SeverityCritical)
		is.Equal(rows[0].CanonicalID, "CVE-2023-24538")
		is.True(rows[0].CVSSScore != nil && *rows[0].CVSSScore == 10)
	})

	t.Run("Negligible with only NVD CVSS stays LOW but shows NVD's score", func(t *testing.T) {
		is := is.New(t)
		rows := Rows([]Finding{{
			Purl: "pkg:deb/debian/bash@5.1-2", VulnerabilityID: "CVE-2022-3715",
			Metadata:        md("debian:distro:debian:11", "CVE-2022-3715", "Negligible", "bash"),
			RelatedMetadata: []*vulnerability.Metadata{md("nvd:cpe", "CVE-2022-3715", "High", "", critVector)},
		}})
		is.Equal(rows[0].Severity, vuln.SeverityLow)
		is.True(rows[0].CVSSScore != nil && *rows[0].CVSSScore == 10)
	})

	t.Run("no CVSS anywhere falls back to the source label; Negligible reads as LOW", func(t *testing.T) {
		is := is.New(t)
		rows := Rows([]Finding{{
			Purl: "pkg:deb/debian/apt@2.2.4", VulnerabilityID: "CVE-2011-3374",
			Metadata: md("debian:distro:debian:11", "CVE-2011-3374", "Negligible", "apt text"),
		}})
		is.Equal(rows[0].Severity, vuln.SeverityLow)
		is.True(rows[0].CVSSScore == nil)
	})

	t.Run("GHSA canonicalises to its CVE alias and keeps references", func(t *testing.T) {
		is := is.New(t)
		m := md("github:language:python", "GHSA-9wx4-h78v-vm56", "Medium", "requests leaks", medVector)
		m.DataSource = "https://github.com/advisories/GHSA-9wx4-h78v-vm56"
		m.URLs = []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-35195", m.DataSource}
		rows := Rows([]Finding{{
			Purl: "pkg:pypi/requests@2.31.0", VulnerabilityID: "GHSA-9wx4-h78v-vm56",
			Related: []string{"CVE-2024-35195"}, Metadata: m,
		}})
		r := rows[0]
		is.Equal(r.Aliases, []string{"CVE-2024-35195"})
		is.Equal(r.CanonicalID, "CVE-2024-35195")
		is.Equal(r.Severity, vuln.SeverityMedium)
		is.Equal(len(r.References), 2) // duplicate URL collapsed
		is.Equal(r.References[0], vuln.Reference{Type: "ADVISORY", URL: m.DataSource})
	})
}

func TestSummarize(t *testing.T) {
	is := is.New(t)
	is.Equal(summarize("First line.\nSecond line."), "First line.")
	long := strings.Repeat("word ", 100)
	s := summarize(long)
	is.True(len([]rune(s)) <= summaryMaxRunes+1)
	is.True(strings.HasSuffix(s, "…"))
	is.True(!strings.Contains(s, "wor…")) // cut on a word boundary
}

func TestMappings(t *testing.T) {
	is := is.New(t)
	got := Mappings([]Finding{
		{Purl: "pkg:pypi/a@1", VulnerabilityID: "V1"},
		{Purl: "pkg:pypi/a@1", VulnerabilityID: "V1", FixedVersion: "2"}, // same pair, second carries the fix
		{Purl: "pkg:pypi/a@1", VulnerabilityID: "V2", FixedVersion: "3"},
		{Purl: "pkg:pypi/b@1", VulnerabilityID: "V1", FixedVersion: "5"},
	})
	is.Equal(got["pkg:pypi/a@1"], []vuln.PackageVulnRef{
		{VulnerabilityID: "V1", FixedVersion: "2"},
		{VulnerabilityID: "V2", FixedVersion: "3"},
	})
	is.Equal(got["pkg:pypi/b@1"], []vuln.PackageVulnRef{{VulnerabilityID: "V1", FixedVersion: "5"}})
}
