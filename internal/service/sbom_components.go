// The bulk component-insert path of ingestion: flattening a CycloneDX BOM
// and COPYing components, hashes, external references, licenses, and
// dependencies. Split out of sbom.go.

package service

import (
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// flatComponent pairs a pre-generated component ID with its source BOM
// component. IDs are generated in Go rather than by the database default
// (gen_random_uuid()) so that parent_id self-references and child FK rows
// (hashes, licenses, ext-refs) can be wired before insertion — which is what
// makes batched CopyFrom possible (CopyFrom supports neither RETURNING nor a
// per-row sequential dependency on the previous row's generated id).
type flatComponent struct {
	id       pgtype.UUID
	parentID pgtype.UUID
	comp     *cdx.Component
	version  string
}

// flattenComponents walks the recursive component tree depth-first, assigning a
// fresh UUID to each component and recording its parent's assigned UUID.
func flattenComponents(components []cdx.Component, parentID pgtype.UUID, mainModule, subjectVersion string) []flatComponent {
	var flat []flatComponent
	var walk func(comps []cdx.Component, parent pgtype.UUID)
	walk = func(comps []cdx.Component, parent pgtype.UUID) {
		for i := range comps {
			comp := &comps[i]
			fc := flatComponent{
				id:       newComponentID(),
				parentID: parent,
				comp:     comp,
				version:  effectiveComponentVersion(comp.Version, comp.Name, comp.PackageURL, mainModule, subjectVersion),
			}
			flat = append(flat, fc)
			if comp.Components != nil {
				walk(*comp.Components, fc.id)
			}
		}
	}
	walk(components, parentID)
	return flat
}

// newComponentID returns a fresh, valid pgtype.UUID for a component row.
func newComponentID() pgtype.UUID {
	return pgtype.UUID{Bytes: uuid.New(), Valid: true}
}

// insertComponentsBatch flattens the component tree and bulk-inserts components
// and their hashes, external references, and licenses via pgx.CopyFrom.
func (s *sbomService) insertComponentsBatch(
	ctx context.Context,
	tx copyFromer,
	q *repository.Queries,
	sbomID pgtype.UUID,
	components []cdx.Component,
	mainModule, subjectVersion, flavor string,
) error {
	flat := flattenComponents(components, pgtype.UUID{}, mainModule, subjectVersion)
	if len(flat) == 0 {
		return nil
	}

	if err := copyComponents(ctx, tx, sbomID, flat, flavor); err != nil {
		return err
	}
	if err := copyComponentHashes(ctx, tx, flat); err != nil {
		return err
	}
	if err := copyComponentExtRefs(ctx, tx, flat); err != nil {
		return err
	}
	return copyComponentLicenses(ctx, tx, q, flat)
}

// colComponentID is the FK column name shared by the component child tables.
const colComponentID = "component_id"

// componentColumns is the column order used by copyComponents; it must match the
// row tuples it builds.
var componentColumns = []string{
	"id", "sbom_id", "parent_id", "bom_ref", "type", "name", "group_name",
	"version", "version_major", "version_minor", "version_patch",
	"purl", "cpe", "description", "scope", "publisher", "copyright",
	"layer_id", "found_by", "source_package", "source_version", "source_purl",
}

func copyComponents(ctx context.Context, tx copyFromer, sbomID pgtype.UUID, flat []flatComponent, flavor string) error {
	rows := make([][]any, len(flat))
	for i, fc := range flat {
		c := fc.comp
		major, minor, patch := parseSemver(fc.version)
		prov := extractComponentProvenance(c.Properties, c.PackageURL, flavor)
		rows[i] = []any{
			fc.id, sbomID, fc.parentID, textOrNull(c.BOMRef), string(c.Type), c.Name, textOrNull(c.Group),
			textOrNull(fc.version), intOrNull(major), intOrNull(minor), intOrNull(patch),
			textOrNull(c.PackageURL), textOrNull(c.CPE), textOrNull(c.Description), textOrNull(string(c.Scope)),
			textOrNull(c.Publisher), textOrNull(c.Copyright),
			prov.layerID, prov.foundBy, prov.sourcePackage, prov.sourceVersion, prov.sourcePurl,
		}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"component"}, componentColumns, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("copying components: %w", err)
	}
	return nil
}

// componentProvenance holds syft-derived provenance fields extracted from a
// component's CycloneDX properties, normalized across package ecosystems.
type componentProvenance struct {
	layerID       pgtype.Text
	foundBy       pgtype.Text
	sourcePackage pgtype.Text
	sourceVersion pgtype.Text
	sourcePurl    pgtype.Text
}

// extractComponentProvenance reads syft-emitted properties (layer, discovery
// tool, and origin/source package) from a component and normalizes the
// upstream "source package" concept across deb/apk/rpm ecosystems. flavor is
// the image flavor string (e.g. "debian-12"), used to build source_purl.
func extractComponentProvenance(props *[]cdx.Property, purl, flavor string) componentProvenance {
	propSets := [][]cdx.Property{propertySlice(props)}

	layerID := findPropValue(propSets, []string{"syft:location:0:layerID"})
	foundBy := findPropValue(propSets, []string{"syft:package:foundBy"})

	var srcPkg, srcVersion string
	switch purlType(purl) {
	case purlTypeDeb:
		srcPkg = findPropValue(propSets, []string{"syft:metadata:source"})
		srcVersion = findPropValue(propSets, []string{"syft:metadata:sourceVersion"})
	case purlTypeAPK:
		srcPkg = findPropValue(propSets, []string{"syft:metadata:originPackage"})
	case purlTypeRPM:
		if sourceRpm := findPropValue(propSets, []string{"syft:metadata:sourceRpm"}); sourceRpm != "" {
			srcPkg, srcVersion = parseSourceRpm(sourceRpm)
		}
	}

	var sourcePurl string
	if srcPkg != "" {
		sourcePurl = buildSourcePurl(purlType(purl), srcPkg, srcVersion, flavor)
	}

	return componentProvenance{
		layerID:       textOrNull(layerID),
		foundBy:       textOrNull(foundBy),
		sourcePackage: textOrNull(srcPkg),
		sourceVersion: textOrNull(srcVersion),
		sourcePurl:    textOrNull(sourcePurl),
	}
}

// parseSourceRpm splits an rpm "sourceRpm" property (e.g.
// "openssl-libs-1.1.1k-7.el8.src.rpm") into source package name and
// version. The package name may itself contain hyphens, so the split is
// anchored from the right: the last two hyphen-separated segments are
// version and release. source_version is reported as "version-release"
// (e.g. "1.1.1k-7.el8"), matching the conventional rpm NVR version string.
func parseSourceRpm(sourceRpm string) (name, version string) {
	s := strings.TrimSuffix(sourceRpm, ".src.rpm")
	if s == sourceRpm {
		return "", "" // unexpected suffix; nothing reliable to parse
	}
	idx2 := strings.LastIndex(s, "-")
	if idx2 < 0 {
		return s, ""
	}
	release := s[idx2+1:]
	rest := s[:idx2]
	idx1 := strings.LastIndex(rest, "-")
	if idx1 < 0 {
		return rest, release
	}
	return rest[:idx1], rest[idx1+1:] + "-" + release
}

// buildSourcePurl constructs a purl for the normalized upstream source
// package, mirroring the purl conventions syft itself uses: type matches
// the binary package's ecosystem, namespace is the OS name, and a
// distro=<flavor> qualifier records the OS/version the artifact was built
// against. Returns "" if pkgType or pkg is empty.
func buildSourcePurl(pkgType, pkg, version, flavor string) string {
	if pkgType == "" || pkg == "" {
		return ""
	}
	var p string
	if namespace, _, ok := strings.Cut(flavor, "-"); ok && namespace != "" {
		p = fmt.Sprintf("pkg:%s/%s/%s", pkgType, namespace, pkg)
	} else {
		p = fmt.Sprintf("pkg:%s/%s", pkgType, pkg)
	}
	if version != "" {
		p += "@" + version
	}
	if flavor != "" && flavor != flavorUnknown {
		p += "?distro=" + flavor
	}
	return p
}

func copyComponentHashes(ctx context.Context, tx copyFromer, flat []flatComponent) error {
	var rows [][]any
	for _, fc := range flat {
		if fc.comp.Hashes == nil {
			continue
		}
		for _, h := range *fc.comp.Hashes {
			rows = append(rows, []any{fc.id, string(h.Algorithm), h.Value})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"component_hash"},
		[]string{colComponentID, "algorithm", "value"}, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("copying component hashes: %w", err)
	}
	return nil
}

func copyComponentExtRefs(ctx context.Context, tx copyFromer, flat []flatComponent) error {
	var rows [][]any
	for _, fc := range flat {
		if fc.comp.ExternalReferences == nil {
			continue
		}
		for _, ref := range *fc.comp.ExternalReferences {
			rows = append(rows, []any{fc.id, string(ref.Type), ref.URL, textOrNull(ref.Comment)})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"external_reference"},
		[]string{colComponentID, "type", "url", "comment"}, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("copying external references: %w", err)
	}
	return nil
}

// copyComponentLicenses resolves each distinct license once (the upsert can't be
// expressed as a COPY because it needs ON CONFLICT) and then bulk-inserts the
// component_license join rows.
func copyComponentLicenses(ctx context.Context, tx copyFromer, q *repository.Queries, flat []flatComponent) error {
	licenseIDs := make(map[string]pgtype.UUID)
	var joinRows [][]any

	for _, fc := range flat {
		if fc.comp.Licenses == nil {
			continue
		}
		seen := make(map[string]struct{})
		for _, choice := range *fc.comp.Licenses {
			if choice.License == nil {
				continue
			}
			lic := choice.License
			spdxID, displayName := NormalizeLicense(lic.ID, lic.Name)
			key := licenseKey(spdxID, displayName)

			licenseID, ok := licenseIDs[key]
			if !ok {
				var err error
				licenseID, err = upsertLicense(ctx, q, spdxID, displayName, lic.URL)
				if err != nil {
					return err
				}
				licenseIDs[key] = licenseID
			}

			// Skip duplicate (component, license) pairs; the join table PK
			// would otherwise reject them (CopyFrom has no ON CONFLICT).
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			joinRows = append(joinRows, []any{fc.id, licenseID})
		}
	}

	if len(joinRows) == 0 {
		return nil
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"component_license"},
		[]string{colComponentID, "license_id"}, pgx.CopyFromRows(joinRows)); err != nil {
		return fmt.Errorf("copying component licenses: %w", err)
	}
	return nil
}

// licenseKey derives a stable dedup key for a normalized license.
func licenseKey(spdxID, displayName string) string {
	if spdxID != "" {
		return "spdx:" + spdxID
	}
	return "name:" + displayName
}

// upsertLicense resolves a license to its ID, inserting it if new.
func upsertLicense(ctx context.Context, q *repository.Queries, spdxID, displayName, url string) (pgtype.UUID, error) {
	if spdxID != "" {
		id, err := q.UpsertLicenseBySPDX(ctx, repository.UpsertLicenseBySPDXParams{
			SpdxID: pgtype.Text{String: spdxID, Valid: true},
			Name:   displayName,
			Url:    textOrNull(url),
		})
		if err != nil {
			return pgtype.UUID{}, fmt.Errorf("upserting license: %w", err)
		}
		return id, nil
	}
	id, err := q.UpsertLicenseByName(ctx, repository.UpsertLicenseByNameParams{
		Name: displayName,
		Url:  textOrNull(url),
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("upserting license: %w", err)
	}
	return id, nil
}

func (s *sbomService) insertDependencies(
	ctx context.Context,
	q *repository.Queries,
	sbomID pgtype.UUID,
	deps []cdx.Dependency,
) error {
	for _, dep := range deps {
		if dep.Dependencies == nil {
			continue
		}
		for _, target := range *dep.Dependencies {
			if err := q.InsertDependency(ctx, repository.InsertDependencyParams{
				SbomID:    sbomID,
				Ref:       dep.Ref,
				DependsOn: target,
			}); err != nil {
				return fmt.Errorf("inserting dependency: %w", err)
			}
		}
	}
	return nil
}
