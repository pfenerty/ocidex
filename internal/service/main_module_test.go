package service

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

// TestFlattenComponentsSplicesMainModuleVersionIntoPurl is the end-to-end
// ingest assertion for the reported kustomize-controller case: the main module
// arrives versionless and must be persisted with the image tag in its purl,
// while a submodule and an unrelated component are left untouched.
func TestFlattenComponentsSplicesMainModuleVersionIntoPurl(t *testing.T) {
	is := is.New(t)

	components := []cdx.Component{
		{
			Name:       "github.com/fluxcd/kustomize-controller",
			Version:    "",
			PackageURL: "pkg:golang/github.com/fluxcd/kustomize-controller",
		},
		{
			Name:       "github.com/fluxcd/kustomize-controller/api",
			Version:    "v1.9.0",
			PackageURL: "pkg:golang/github.com/fluxcd/kustomize-controller/api@v1.9.0",
		},
		{
			Name:       "github.com/fluxcd/pkg/tar",
			Version:    "v1.2.0",
			PackageURL: "pkg:golang/github.com/fluxcd/pkg/tar@v1.2.0",
		},
	}

	flat := flattenComponents(components, pgtype.UUID{},
		"github.com/fluxcd/kustomize-controller", "v1.9.5")
	is.Equal(len(flat), 3)

	// Main module: version backfilled from the image tag, and now carried in
	// the purl so the vuln refresh can match it.
	is.Equal(flat[0].version, "v1.9.5")
	is.Equal(flat[0].purl, "pkg:golang/github.com/fluxcd/kustomize-controller@v1.9.5")

	// Submodule and unrelated dependency keep their own versions and purls.
	is.Equal(flat[1].purl, "pkg:golang/github.com/fluxcd/kustomize-controller/api@v1.9.0")
	is.Equal(flat[2].purl, "pkg:golang/github.com/fluxcd/pkg/tar@v1.2.0")
}
