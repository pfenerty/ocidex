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

// cycloneDXFixture is a minimal CycloneDX 1.4 document used in tests.
type cycloneDXFixture struct {
	Metadata struct {
		Component *struct {
			BomRef string `json:"bom-ref"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		BomRef string `json:"bom-ref"`
		Name   string `json:"name"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// parseSBOMFixture reads a CycloneDX JSON fixture and extracts the inputs
// that computeRootsAndDirect expects, mirroring what the service does with
// GetSBOMMetadataBomRef + buildDepEdgeMaps + ListSBOMPackages in production.
func parseSBOMFixture(t *testing.T, name string) (metaBomRef string, outEdges map[string][]string, inEdge map[string]int, pkgs []repository.ListSBOMPackagesRow) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sbom_roots", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var doc cycloneDXFixture
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}

	if doc.Metadata.Component != nil {
		metaBomRef = doc.Metadata.Component.BomRef
	}

	outEdges = make(map[string][]string)
	inEdge = make(map[string]int)
	for _, dep := range doc.Dependencies {
		for _, child := range dep.DependsOn {
			outEdges[dep.Ref] = append(outEdges[dep.Ref], child)
			inEdge[child]++
		}
	}

	for _, c := range doc.Components {
		pkgs = append(pkgs, repository.ListSBOMPackagesRow{
			BomRef: pgtype.Text{String: c.BomRef, Valid: c.BomRef != ""},
			Name:   c.Name,
		})
	}
	return
}

func TestComputeRootsAndDirect(t *testing.T) {
	tests := []struct {
		fixture     string
		wantRoots   []string
		wantDirects []string // refs that must appear in directSet
		wantDirLen  int      // total expected size of directSet
	}{
		{
			// Syft: metadata.component.bom-ref is the dependency-graph root
			// → roots = direct children, all isDirect
			fixture:     "syft_metadata_bomref_in_graph.json",
			wantRoots:   []string{"pkg:deb/debian/curl@7.81.0", "pkg:deb/debian/libssl@1.1.1"},
			wantDirects: []string{"pkg:deb/debian/curl@7.81.0", "pkg:deb/debian/libssl@1.1.1"},
			wantDirLen:  2,
		},
		{
			// Trivy: metadata.component.bom-ref is a UUID, same anchoring pattern
			// → roots = direct children sorted by name, all isDirect
			fixture:     "trivy_metadata_bomref_in_graph.json",
			wantRoots:   []string{"pkg:apk/alpine/busybox@1.36.1", "pkg:apk/alpine/musl@1.2.4"},
			wantDirects: []string{"pkg:apk/alpine/musl@1.2.4", "pkg:apk/alpine/busybox@1.36.1"},
			wantDirLen:  2,
		},
		{
			// apko: metadata.component.bom-ref present in metadata but has NO outgoing dep edges
			// → fall back to zero-in-degree nodes (bom-refs, sorted by name); no directSet entries
			fixture:    "apko_metadata_bomref_no_edges.json",
			wantRoots:  []string{"pkg:apk/wolfi/glibc@2.38", "pkg:apk/wolfi/libssl@3.1.4"},
			wantDirLen: 0,
		},
		{
			// Hand-written CycloneDX with no metadata.component at all
			// → fall back to zero-in-degree; only comp-alpha has in-degree 0
			fixture:    "no_metadata_bomref.json",
			wantRoots:  []string{"comp-alpha"},
			wantDirLen: 0,
		},
		{
			// metadata.component.bom-ref is set but never appears as ref in dependencies[]
			// → has no outEdges entry → fall back; metaBomRef excluded from roots itself
			fixture:    "metadata_bomref_not_in_deps.json",
			wantRoots:  []string{"pkg-a"},
			wantDirLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			is := is.New(t)
			metaBomRef, outEdges, inEdge, pkgs := parseSBOMFixture(t, tt.fixture)
			roots, directSet := computeRootsAndDirect(outEdges, inEdge, metaBomRef, pkgs)

			// Roots are sorted by name; compare directly.
			is.Equal(roots, tt.wantRoots)

			// Every expected direct must be present.
			for _, ref := range tt.wantDirects {
				is.True(directSet[ref])
			}
			// No unexpected directs.
			is.Equal(len(directSet), tt.wantDirLen)
		})
	}
}
