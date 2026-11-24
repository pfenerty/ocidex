package service

import (
	"testing"

	"github.com/matryer/is"
)

// A versioned package replaced under a new name (go-1.24 -> go-1.25) is one
// modified change; its closes must come from the old name's findings, which
// only previousPurl still points at.
func TestAnnotateVulnsFollowsReconciledRename(t *testing.T) {
	is := is.New(t)
	oldPurl, newPurl := "pkg:apk/wolfi/go-1.24@1.24.9", "pkg:apk/wolfi/go-1.25@1.25.1"
	ver := func(s string) *string { return &s }
	oldMap := map[string]componentIdentity{
		normalizeComponentPurl(oldPurl): {version: ver("1.24.9"), purl: &oldPurl, name: "go-1.24"},
	}
	newMap := map[string]componentIdentity{
		normalizeComponentPurl(newPurl): {version: ver("1.25.1"), purl: &newPurl, name: "go-1.25"},
	}
	entry := diffComponents(SBOMRef{}, SBOMRef{}, oldMap, newMap)
	is.Equal(len(entry.Changes), 1)
	is.Equal(entry.Changes[0].Type, dirModified)

	annotateVulns(&entry,
		sbomVulns{oldPurl: {"CVE-1": "HIGH", "CVE-2": "LOW"}},
		sbomVulns{newPurl: {"CVE-2": "LOW", "CVE-3": "CRITICAL"}},
	)
	is.Equal(entry.Changes[0].Closes, []ChangeVuln{{ID: "CVE-1", Severity: "HIGH"}})
	is.Equal(entry.Changes[0].Opens, []ChangeVuln{{ID: "CVE-3", Severity: "CRITICAL"}})
	is.Equal(*entry.Vulns, ChangelogVulnTotals{Closed: SeverityTally{High: 1}, Opened: SeverityTally{Critical: 1}})
}
