package repository

import (
	"strings"
	"testing"
)

// TestSBOMComponentSeverityScopeMatchesTheVulnQuery holds ListSBOMComponentsPage's
// severity scope equal to ListSBOMComponentVulns'.
//
// The two exist for different jobs on the same page: the vuln query produces the
// counts decorateComponentVulns puts in each row's badge, and the components
// query produces the key those rows are *ordered* by (ocidex-unn8.11). Nothing
// forces them to agree, and a divergence is silent — the badges stay right, the
// ordering quietly stops matching them, and the failure looks like a sorting
// bug rather than a scope bug. ocidex-unn8.2 widened the scope from purl to
// purl ∪ source_purl in one of them; the next such change must move both.
//
// Only the scope CTE is compared. The two diverge deliberately after it: the
// vuln query returns one row per finding with fixed_version and
// matched_via_source, while the components query folds findings into per-purl
// counts. Those are different shapes for different jobs. What must not diverge
// is which (component purl, package purl) pairs are considered at all.
func TestSBOMComponentSeverityScopeMatchesTheVulnQuery(t *testing.T) {
	page := scopeCTE(t, listSBOMComponentsPage)
	vulns := scopeCTE(t, listSBOMComponentVulns)

	// The queries take their sbom id through different placeholders — the vuln
	// query uses it twice and nothing else, so sqlc numbers it $1, while the
	// components query has cursor and sort params around it. That is the one
	// difference the scopes are allowed to have.
	page = strings.ReplaceAll(page, "$1", "SBOM_ID")
	vulns = strings.ReplaceAll(vulns, "$1", "SBOM_ID")

	if page != vulns {
		t.Errorf("scope CTEs have diverged, so the package list's severity ordering no longer\n"+
			"matches the counts its badges show.\n\nListSBOMComponentsPage:\n%s\n\nListSBOMComponentVulns:\n%s", page, vulns)
	}
}

// scopeCTE extracts the text of the `scope` CTE — everything between
// "WITH scope AS (" and the matching close paren — normalised so the comparison
// is about the query rather than about indentation.
func scopeCTE(t *testing.T, query string) string {
	t.Helper()

	const open = "WITH scope AS ("
	start := strings.Index(query, open)
	if start < 0 {
		t.Fatalf("query has no `WITH scope AS (` CTE:\n%s", query)
	}
	body := query[start+len(open):]

	depth := 1
	for i, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return normalizeSQL(body[:i])
			}
		}
	}
	t.Fatal("unterminated scope CTE")
	return ""
}

// normalizeSQL reduces a statement to the parts that change its meaning:
// comments and layout are dropped.
func normalizeSQL(s string) string {
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		kept = append(kept, line)
	}
	return strings.Join(strings.Fields(strings.Join(kept, " ")), " ")
}
