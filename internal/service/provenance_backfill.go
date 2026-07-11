package service

import (
	"bytes"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
)

// ExistingComponentRef is the narrow shape of an already-persisted component
// row needed to match it back against a decoded raw_bom, decoupled from the
// generated repository types so this package stays unit-testable without a DB.
type ExistingComponentRef struct {
	ID     pgtype.UUID
	BOMRef string
	Purl   string
}

// ProvenanceUpdate carries the provenance columns to write back for a single
// existing component row. Fields are exported (unlike componentProvenance)
// so callers outside this package, such as cmd/backfill-provenance, can read
// them without exposing ingest-path internals.
type ProvenanceUpdate struct {
	ComponentID   pgtype.UUID
	LayerID       pgtype.Text
	FoundBy       pgtype.Text
	SourcePackage pgtype.Text
	SourceVersion pgtype.Text
	SourcePurl    pgtype.Text
}

// bomComponentByRef walks the recursive component tree depth-first and
// indexes components by bom-ref, read-only (no new IDs assigned, unlike
// flattenComponents). Components with an empty bom-ref are skipped.
// Components sharing a bom-ref with another component are unmatchable and
// removed from the map; their refs are reported in dupRefs.
func bomComponentByRef(components []cdx.Component) (byRef map[string]*cdx.Component, dupRefs []string) {
	byRef = map[string]*cdx.Component{}
	seenDup := map[string]bool{}

	var walk func(comps []cdx.Component)
	walk = func(comps []cdx.Component) {
		for i := range comps {
			comp := &comps[i]
			if comp.BOMRef != "" {
				if _, exists := byRef[comp.BOMRef]; exists {
					delete(byRef, comp.BOMRef)
					if !seenDup[comp.BOMRef] {
						dupRefs = append(dupRefs, comp.BOMRef)
						seenDup[comp.BOMRef] = true
					}
				} else if !seenDup[comp.BOMRef] {
					byRef[comp.BOMRef] = comp
				}
			}
			if comp.Components != nil {
				walk(*comp.Components)
			}
		}
	}
	walk(components)
	return byRef, dupRefs
}

// ComputeProvenanceUpdates decodes rawBom and, for each existing component
// row that has a matching bom-ref in the decoded tree, re-derives provenance
// via extractComponentProvenance. Rows with an empty bom-ref, rows whose
// bom-ref cannot be found (or is ambiguous), and matches that yield no
// provenance properties are skipped and logged; they do not cause an error.
func ComputeProvenanceUpdates(rawBom []byte, flavor string, existing []ExistingComponentRef) ([]ProvenanceUpdate, error) {
	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(bytes.NewReader(rawBom), cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		return nil, fmt.Errorf("decoding raw_bom: %w", err)
	}

	var byRef map[string]*cdx.Component
	var dupRefs []string
	if bom.Components != nil {
		byRef, dupRefs = bomComponentByRef(*bom.Components)
	}
	for _, ref := range dupRefs {
		slog.Warn("backfill-provenance: skipping duplicate bom-ref", "bomRef", ref)
	}

	var updates []ProvenanceUpdate
	for _, ex := range existing {
		if ex.BOMRef == "" {
			slog.Warn("backfill-provenance: skipping component with empty bom-ref", "componentID", ex.ID)
			continue
		}
		comp, ok := byRef[ex.BOMRef]
		if !ok {
			slog.Warn("backfill-provenance: bom-ref not found in raw_bom", "componentID", ex.ID, "bomRef", ex.BOMRef)
			continue
		}

		prov := extractComponentProvenance(comp.Properties, comp.PackageURL, flavor)
		if !prov.layerID.Valid && !prov.foundBy.Valid && !prov.sourcePackage.Valid &&
			!prov.sourceVersion.Valid && !prov.sourcePurl.Valid {
			continue
		}

		updates = append(updates, ProvenanceUpdate{
			ComponentID:   ex.ID,
			LayerID:       prov.layerID,
			FoundBy:       prov.foundBy,
			SourcePackage: prov.sourcePackage,
			SourceVersion: prov.sourceVersion,
			SourcePurl:    prov.sourcePurl,
		})
	}

	return updates, nil
}
