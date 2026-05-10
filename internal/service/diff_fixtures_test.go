package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// cycloneDXDiffFixture is a minimal CycloneDX 1.4 document used for diff tests.
// Mirrors what ListSBOMPackages would return at the rows we care about.
type cycloneDXDiffFixture struct {
	Components []struct {
		BomRef  string `json:"bom-ref"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"components"`
}

// loadDiffFixture reads a CycloneDX JSON fixture and returns rows shaped like
// ListSBOMPackagesRow so they can drive diffComponents through the same path
// the service uses in production.
func loadDiffFixture(t *testing.T, name string) []repository.ListSBOMPackagesRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sbom_diff", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var doc cycloneDXDiffFixture
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	rows := make([]repository.ListSBOMPackagesRow, 0, len(doc.Components))
	for _, c := range doc.Components {
		rows = append(rows, repository.ListSBOMPackagesRow{
			BomRef:    pgtype.Text{String: c.BomRef, Valid: c.BomRef != ""},
			Type:      c.Type,
			Name:      c.Name,
			GroupName: pgtype.Text{String: c.Group, Valid: c.Group != ""},
			Version:   pgtype.Text{String: c.Version, Valid: c.Version != ""},
			Purl:      pgtype.Text{String: c.Purl, Valid: c.Purl != ""},
		})
	}
	return rows
}

// TestDiffComponents_AlpineVersionDriftFixture exercises the full
// loadFixture → buildPackageMap → diffComponents path against a paired
// pair of CycloneDX fixtures that differ only in their distro qualifier
// version. Guards ADR-0019 Rule 1 distro normalization end-to-end.
func TestDiffComponents_AlpineVersionDriftFixture(t *testing.T) {
	is := is.New(t)

	oldRows := loadDiffFixture(t, "alpine-3.14.json")
	newRows := loadDiffFixture(t, "alpine-3.15.json")

	entry := diffComponents(
		SBOMRef{ID: "from"},
		SBOMRef{ID: "to"},
		buildPackageMap(oldRows),
		buildPackageMap(newRows),
	)

	// Four packages are upgraded across the alpine 3.14.3 → 3.15.0 boundary.
	// One package (openssl) is removed; one package (ca-certificates) is added.
	is.Equal(entry.Summary.Upgraded, 4)
	is.Equal(entry.Summary.Removed, 1)
	is.Equal(entry.Summary.Added, 1)
	is.Equal(entry.Summary.Downgraded, 0)
	is.Equal(entry.Summary.Modified, 0)

	// Spot-check a few specific entries.
	upgradedNames := map[string]bool{}
	addedNames := map[string]bool{}
	removedNames := map[string]bool{}
	for _, c := range entry.Changes {
		switch c.Direction {
		case dirUpgraded:
			upgradedNames[c.Name] = true
		case dirAdded:
			addedNames[c.Name] = true
		case dirRemoved:
			removedNames[c.Name] = true
		}
	}
	is.True(upgradedNames["alpine-baselayout"])
	is.True(upgradedNames["busybox"])
	is.True(upgradedNames["musl"])
	is.True(upgradedNames["libssl1.1"])
	is.True(addedNames["ca-certificates"])
	is.True(removedNames["openssl"])
}
