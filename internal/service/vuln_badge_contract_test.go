package service

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

// vulnBadge is the normalised thing every surface in the contract below has to
// produce: something the UI can render as a VulnCountBadges cluster and a
// coloured SeverityPill.
type vulnBadge struct {
	key      string // purl or advisory id, so a failure names the row
	count    int64
	severity string
}

// TestVulnBadgeSurfaces_CarryCounts is the vulnerability analogue of
// web/src/components/ui/tabBarContract.test.ts: a contract over every service
// path whose UI renders VulnCountBadges or a SeverityPill.
//
// The bug class it exists for (ocidex-unn8.1) is a column wired to a field the
// server never populates. Nothing else catches it: GetSBOMDependencies returned
// a perfectly well-formed graph with every node's VulnCount silently zero, and
// every existing service test passed — the tree view's Vulns column was em
// dashes on an SBOM with 86 known vulnerabilities. A data path that does
// nothing is not an assertion failure, the same way a dead CSS class isn't.
//
// So the assertion is deliberately shallow and total rather than deep and
// partial: every surface, given a fixture that *has* a finding, must return
// items carrying both a non-zero count and a severity. Dropping the
// decorateComponentVulns call from any component path, or the severity mapping
// from either vulns list, fails exactly the row that lost it.
//
// Adding a new badge surface means adding a row here. If a surface is missing
// from this table, the next one to lose its counts ships the same way this one
// did.
func TestVulnBadgeSurfaces_CarryCounts(t *testing.T) {
	surfaces := []struct {
		name string
		call func(*searchService) ([]vulnBadge, error)
	}{
		{
			name: "SBOM component list (SBOMDetail/PackagesTab, unpaged)",
			call: func(svc *searchService) ([]vulnBadge, error) {
				items, err := svc.ListSBOMComponents(context.Background(), fixtureSbomID, VisibilityFilter{})
				return componentVulnBadges(items), err
			},
		},
		{
			name: "SBOM component list (SBOMDetail/PackagesTab, keyset page)",
			call: func(svc *searchService) ([]vulnBadge, error) {
				page, err := svc.ListSBOMComponentsPage(context.Background(), fixtureSbomID, ComponentPage{Limit: 10}, VisibilityFilter{})
				return componentVulnBadges(page.Data), err
			},
		},
		{
			name: "SBOM dependency graph (SBOMDetail/DependencyTreeView)",
			call: func(svc *searchService) ([]vulnBadge, error) {
				graph, err := svc.GetSBOMDependencies(context.Background(), fixtureSbomID, VisibilityFilter{})
				return componentVulnBadges(graph.Nodes), err
			},
		},
		{
			name: "SBOM vulnerabilities tab (ocidex-unn8.4)",
			call: func(svc *searchService) ([]vulnBadge, error) {
				res, err := svc.ListSBOMVulns(context.Background(), fixtureSbomID, SBOMVulnParams{Limit: 10}, VisibilityFilter{})
				out := make([]vulnBadge, 0, len(res.Data))
				for _, v := range res.Data {
					out = append(out, vulnBadge{key: v.CanonicalID, count: v.AffectedPackageCount, severity: v.Severity})
				}
				return out, err
			},
		},
		{
			name: "artifact vulnerabilities tab (ocidex-unn8.6)",
			call: func(svc *searchService) ([]vulnBadge, error) {
				res, err := svc.ListArtifactVulns(context.Background(), fixtureArtifactID, ArtifactVulnParams{Limit: 10}, VisibilityFilter{})
				out := make([]vulnBadge, 0, len(res.Data))
				for _, v := range res.Data {
					// The artifact tab's distinguishing badge is the version
					// count — "which versions carry this" is why it exists.
					out = append(out, vulnBadge{key: v.CanonicalID, count: v.AffectedVersionCount, severity: v.Severity})
				}
				return out, err
			},
		},
	}

	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			is := is.New(t)

			badges, err := s.call(&searchService{db: vulnBadgeFixtureDB()})
			is.NoErr(err)

			// An empty surface would pass every per-item assertion below, which
			// is precisely how the dependency graph hid its gap.
			if len(badges) == 0 {
				t.Fatal("surface returned no items; the fixture has a finding, so it must return at least one")
			}
			for _, b := range badges {
				if b.count == 0 {
					t.Errorf("%s: count is 0, so the UI renders an em dash on a row that has a finding", b.key)
				}
				if b.severity == "" {
					t.Errorf("%s: severity is empty, so the pill renders uncoloured on a row that has a finding", b.key)
				}
			}
		})
	}
}

// componentVulnBadges projects the component-shaped surfaces onto the same view
// as the advisory-shaped ones.
func componentVulnBadges(items []ComponentSummary) []vulnBadge {
	out := make([]vulnBadge, 0, len(items))
	for _, c := range items {
		purl := ""
		if c.Purl != nil {
			purl = *c.Purl
		}
		out = append(out, vulnBadge{key: purl, count: int64(c.VulnCount), severity: c.MaxSeverity})
	}
	return out
}

var (
	fixtureSbomID     = pgtype.UUID{Bytes: [16]byte{0xb1}, Valid: true}
	fixtureArtifactID = pgtype.UUID{Bytes: [16]byte{0xb2}, Valid: true}
	fixtureCompID     = pgtype.UUID{Bytes: [16]byte{0xb3}, Valid: true}
)

const (
	fixturePurl   = "pkg:golang/github.com/example/vulnerable@1.0.0"
	fixtureVulnID = "CVE-2024-9999"
)

// vulnBadgeFixtureDB serves one component carrying one HIGH finding to every
// query any of the five surfaces issues. Dispatch is on the sqlc name comment,
// as in TestGetSBOMDependencies_DecoratesVulns.
func vulnBadgeFixtureDB() *fakeDB {
	return &fakeDB{
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return &fakeRow{scanFn: func(dest ...any) error {
				switch {
				case strings.Contains(sql, "IsSBOMVisible :one"),
					strings.Contains(sql, "IsArtifactVisible :one"):
					*(dest[0].(*bool)) = true
				case strings.Contains(sql, "CountSBOMVulns :one"),
					strings.Contains(sql, "CountArtifactVulns :one"):
					*(dest[0].(*int64)) = 1
				}
				// GetSBOMMetadataBomRef and anything else: leave zero.
				return nil
			}}
		},
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			switch {
			case strings.Contains(sql, "ListSBOMComponents :many"),
				strings.Contains(sql, "ListSBOMComponentsPage :many"):
				// Both row shapes start (id, bom_ref, type, name, group, version, purl).
				return &scanFnRows{fns: []func(...any) error{
					func(dest ...any) error {
						*(dest[0].(*pgtype.UUID)) = fixtureCompID
						*(dest[2].(*string)) = "library"
						*(dest[3].(*string)) = "vulnerable"
						*(dest[6].(*pgtype.Text)) = pgtype.Text{String: fixturePurl, Valid: true}
						return nil
					},
				}}, nil

			case strings.Contains(sql, "ListSBOMComponentVulns :many"):
				return &scanFnRows{fns: []func(...any) error{
					func(dest ...any) error {
						*(dest[0].(*string)) = fixturePurl
						*(dest[1].(*string)) = fixtureVulnID
						*(dest[2].(*string)) = fixtureVulnID
						*(dest[3].(*pgtype.Text)) = pgtype.Text{String: sevHigh, Valid: true}
						return nil
					},
				}}, nil

			case strings.Contains(sql, "ListSBOMVulns :many"):
				return &scanFnRows{fns: []func(...any) error{
					func(dest ...any) error {
						*(dest[0].(*string)) = fixtureVulnID
						*(dest[1].(*string)) = fixtureVulnID
						*(dest[2].(*pgtype.Text)) = pgtype.Text{String: sevHigh, Valid: true}
						*(dest[5].(*int64)) = 1 // affected_package_count
						return nil
					},
				}}, nil

			case strings.Contains(sql, "ListArtifactVulns :many"):
				return &scanFnRows{fns: []func(...any) error{
					func(dest ...any) error {
						*(dest[0].(*string)) = fixtureVulnID
						*(dest[1].(*string)) = fixtureVulnID
						*(dest[2].(*pgtype.Text)) = pgtype.Text{String: sevHigh, Valid: true}
						*(dest[5].(*int64)) = 1 // affected_package_count
						*(dest[6].(*int64)) = 1 // affected_version_count
						return nil
					},
				}}, nil

			case strings.Contains(sql, "ListSBOMVulnAffectedPackages :many"):
				return &scanFnRows{fns: []func(...any) error{
					func(dest ...any) error {
						*(dest[0].(*string)) = fixtureVulnID
						*(dest[1].(*string)) = fixturePurl
						*(dest[2].(*string)) = "vulnerable"
						return nil
					},
				}}, nil

			case strings.Contains(sql, "ListArtifactVulnAffectedVersions :many"):
				return &scanFnRows{fns: []func(...any) error{
					func(dest ...any) error {
						*(dest[0].(*string)) = fixtureVulnID
						*(dest[1].(*pgtype.Text)) = pgtype.Text{String: "1.0.0", Valid: true}
						*(dest[2].(*pgtype.UUID)) = fixtureSbomID
						*(dest[3].(*int64)) = 1
						return nil
					},
				}}, nil

			default:
				// ListDependenciesBySBOM and anything else: no rows.
				return emptyRows(), nil
			}
		},
	}
}
