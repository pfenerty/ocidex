package service

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/matryer/is"
)

func TestBomComponentByRef(t *testing.T) {
	is := is.New(t)

	child := []cdx.Component{{BOMRef: "child-ref", Name: "child", Type: cdx.ComponentTypeLibrary}}
	components := []cdx.Component{
		{BOMRef: "parent-ref", Name: "parent", Type: cdx.ComponentTypeLibrary, Components: &child},
		{BOMRef: "", Name: "no-ref", Type: cdx.ComponentTypeLibrary}, // empty bom-ref → skipped
		{BOMRef: "dup-ref", Name: "dup-a", Type: cdx.ComponentTypeLibrary},
		{BOMRef: "dup-ref", Name: "dup-b", Type: cdx.ComponentTypeLibrary},
	}

	byRef, dupRefs := bomComponentByRef(components)

	is.Equal(len(byRef), 2) // parent-ref, child-ref only (no-ref skipped, dup-ref removed)
	is.Equal(byRef["parent-ref"].Name, "parent")
	is.Equal(byRef["child-ref"].Name, "child") // nested tree walked
	_, hasNoRef := byRef["no-ref"]
	is.True(!hasNoRef)
	_, hasDup := byRef["dup-ref"]
	is.True(!hasDup)
	is.Equal(dupRefs, []string{"dup-ref"})
}

func rawBomFromComponents(t *testing.T, components []cdx.Component) []byte {
	t.Helper()
	bom := cdx.NewBOM()
	bom.Components = &components
	b, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal bom: %v", err)
	}
	return b
}

func TestComputeProvenanceUpdates(t *testing.T) {
	is := is.New(t)

	compID := newUUID(t)
	otherID := newUUID(t)

	debProps := []cdx.Property{
		{Name: "syft:location:0:layerID", Value: "sha256:layer1"},
		{Name: "syft:package:foundBy", Value: "deb-db-cataloger"},
		{Name: "syft:metadata:source", Value: "openssl"},
		{Name: "syft:metadata:sourceVersion", Value: "3.0.11-1~deb12u2"},
	}

	t.Run("happy path match", func(t *testing.T) {
		components := []cdx.Component{
			{BOMRef: "ref-1", Name: "libssl3", PackageURL: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", Properties: &debProps},
		}
		raw := rawBomFromComponents(t, components)

		updates, err := ComputeProvenanceUpdates(raw, "debian-12", []ExistingComponentRef{
			{ID: compID, BOMRef: "ref-1", Purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2"},
		})
		is.NoErr(err)
		is.Equal(len(updates), 1)
		is.Equal(updates[0].ComponentID, compID)
		is.Equal(updates[0].LayerID.String, "sha256:layer1")
		is.Equal(updates[0].FoundBy.String, "deb-db-cataloger")
		is.Equal(updates[0].SourcePackage.String, "openssl")
		is.Equal(updates[0].SourceVersion.String, "3.0.11-1~deb12u2")
		is.Equal(updates[0].SourcePurl.String, "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12")
	})

	t.Run("bom-ref not found in raw bom", func(t *testing.T) {
		components := []cdx.Component{
			{BOMRef: "ref-1", Name: "libssl3", PackageURL: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", Properties: &debProps},
		}
		raw := rawBomFromComponents(t, components)

		updates, err := ComputeProvenanceUpdates(raw, "debian-12", []ExistingComponentRef{
			{ID: otherID, BOMRef: "ref-missing", Purl: "pkg:deb/debian/other@1.0"},
		})
		is.NoErr(err)
		is.Equal(len(updates), 0)
	})

	t.Run("empty bom-ref in existing row skipped defensively", func(t *testing.T) {
		components := []cdx.Component{
			{BOMRef: "ref-1", Name: "libssl3", PackageURL: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", Properties: &debProps},
		}
		raw := rawBomFromComponents(t, components)

		updates, err := ComputeProvenanceUpdates(raw, "debian-12", []ExistingComponentRef{
			{ID: compID, BOMRef: "", Purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2"},
		})
		is.NoErr(err)
		is.Equal(len(updates), 0)
	})

	t.Run("matched node with no provenance properties not included", func(t *testing.T) {
		components := []cdx.Component{
			{BOMRef: "ref-1", Name: "no-props", PackageURL: "pkg:deb/debian/no-props@1.0"},
		}
		raw := rawBomFromComponents(t, components)

		updates, err := ComputeProvenanceUpdates(raw, "debian-12", []ExistingComponentRef{
			{ID: compID, BOMRef: "ref-1", Purl: "pkg:deb/debian/no-props@1.0"},
		})
		is.NoErr(err)
		is.Equal(len(updates), 0)
	})

	t.Run("malformed raw bom returns error not panic", func(t *testing.T) {
		updates, err := ComputeProvenanceUpdates([]byte("not json"), "debian-12", []ExistingComponentRef{
			{ID: compID, BOMRef: "ref-1", Purl: "pkg:deb/debian/libssl3@1.0"},
		})
		is.True(err != nil)
		is.Equal(len(updates), 0)
	})

	t.Run("multiple components only matching subset returned", func(t *testing.T) {
		components := []cdx.Component{
			{BOMRef: "ref-1", Name: "libssl3", PackageURL: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", Properties: &debProps},
			{BOMRef: "ref-2", Name: "unmatched", PackageURL: "pkg:deb/debian/unmatched@1.0", Properties: &debProps},
		}
		raw := rawBomFromComponents(t, components)

		updates, err := ComputeProvenanceUpdates(raw, "debian-12", []ExistingComponentRef{
			{ID: compID, BOMRef: "ref-1", Purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2"},
		})
		is.NoErr(err)
		is.Equal(len(updates), 1)
		is.Equal(updates[0].ComponentID, compID)
	})

	t.Run("duplicate bom-ref in bom yields no update for that ref", func(t *testing.T) {
		components := []cdx.Component{
			{BOMRef: "dup-ref", Name: "dup-a", PackageURL: "pkg:deb/debian/dup-a@1.0", Properties: &debProps},
			{BOMRef: "dup-ref", Name: "dup-b", PackageURL: "pkg:deb/debian/dup-b@1.0", Properties: &debProps},
			{BOMRef: "ref-ok", Name: "ok", PackageURL: "pkg:deb/debian/ok@1.0", Properties: &debProps},
		}
		raw := rawBomFromComponents(t, components)

		updates, err := ComputeProvenanceUpdates(raw, "debian-12", []ExistingComponentRef{
			{ID: compID, BOMRef: "dup-ref", Purl: "pkg:deb/debian/dup-a@1.0"},
			{ID: otherID, BOMRef: "ref-ok", Purl: "pkg:deb/debian/ok@1.0"},
		})
		is.NoErr(err)
		is.Equal(len(updates), 1)
		is.Equal(updates[0].ComponentID, otherID)
	})
}
