// Package vuln holds the domain types and Postgres store of the package-keyed
// vulnerability store. Per-SBOM vulnerability status is derived by joining
// component.purl against the store at read time, so a newly disclosed CVE
// reaches every affected SBOM without re-ingesting it.
//
// Matching itself lives in internal/vuln/grypematch (ADR-049), which only the
// vuln-worker links; this package stays light because the API imports it.
package vuln

import (
	"strings"
	"time"
)

// Row is a vulnerability ready to persist (domain shape; the store adapter
// translates it to repository params).
type Row struct {
	ID          string
	Aliases     []string
	CanonicalID string
	Summary     string
	Details     string
	Severity    string
	CVSSScore   *float32
	CVSSVector  string
	Published   time.Time
	Modified    time.Time
	Raw         []byte
	References  []Reference
}

// Reference is one link attached to a vulnerability (advisory, web page, …).
type Reference struct {
	Type string
	URL  string
}

// Severity is one CVSS entry, e.g. {Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/..."}.
// Score holds the vector string, from which DeriveSeverity computes the base score.
type Severity struct {
	Type  string
	Score string
}

// PackageVulnRef is one (purl → vulnerability) mapping row.
type PackageVulnRef struct {
	VulnerabilityID string
	FixedVersion    string
}

// CanonicalID returns the best stable public identifier for a vulnerability:
// the CVE among its ID and aliases, then a GHSA, then the native ID. The read
// side groups aliased records (GO-…, GHSA-…, CVE-…) by it.
func CanonicalID(id string, aliases []string) string {
	if strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	if strings.HasPrefix(id, "GHSA-") {
		return id
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "GHSA-") {
			return a
		}
	}
	return id
}
