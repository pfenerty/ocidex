package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

// backfillLicenseNames re-derives every license stored without an SPDX id with
// ExpandLicense (ocidex-wb5k). A name that comes back as itself is left alone.
// Otherwise each component linked to it is linked to the licenses it really
// names (an expression's members, an alias's SPDX license, a name with its
// trailing comma dropped, or nothing for a fragment), and the old row is
// deleted, taking its links and rollup rows with it.
//
// Each step is idempotent and the old row goes last, so a run that stops
// part-way leaves the old license in place to be finished by the next run.
func backfillLicenseNames(ctx context.Context, repo BackfillRepository, batchSize int32) (BackfillCounts, error) {
	var c BackfillCounts
	after := pgtype.UUID{Valid: true}
	for {
		rows, err := repo.ListNameOnlyLicensesPage(ctx, repository.ListNameOnlyLicensesPageParams{After: after, RowLimit: batchSize})
		if err != nil {
			return c, fmt.Errorf("listing name-only licenses: %w", err)
		}
		for _, row := range rows {
			defs := ExpandLicense("", row.Name, "")
			if len(defs) == 1 && defs[0].spdxID == "" && defs[0].name == row.Name {
				c.Skipped++
				continue
			}
			if err := rewriteLicense(ctx, repo, row.ID, defs); err != nil {
				return c, fmt.Errorf("rewriting license %q: %w", row.Name, err)
			}
			c.Updated++
		}
		if len(rows) < int(batchSize) {
			return c, nil
		}
		after = rows[len(rows)-1].ID
	}
}

// rewriteLicense links old's components to each of defs, then deletes old.
func rewriteLicense(ctx context.Context, repo BackfillRepository, old pgtype.UUID, defs []licenseDef) error {
	keepOld := false
	for _, def := range defs {
		id, err := upsertLicense(ctx, repo, def.spdxID, def.name, "")
		if err != nil {
			return err
		}
		if id == old {
			// One of the names it splits into is itself: its links stay as they are.
			keepOld = true
			continue
		}
		if err := repo.CopyLicenseLinks(ctx, repository.CopyLicenseLinksParams{FromLicense: old, ToLicense: id}); err != nil {
			return fmt.Errorf("copying links: %w", err)
		}
	}
	if keepOld {
		return nil
	}
	if err := repo.DeleteLicenseByID(ctx, old); err != nil {
		return fmt.Errorf("deleting license: %w", err)
	}
	return nil
}

// backfillLicenseExpressions adds the licenses an SBOM's CycloneDX license
// expressions name; Updated counts links actually inserted, so a re-run reports 0. Ingest skipped expression choices before ocidex-nps9.13, so
// those components carry none of them. Links are only added, never removed, and
// components are matched to their rows by bom-ref; one without a bom-ref, or
// with none stored, is counted as skipped.
func backfillLicenseExpressions(ctx context.Context, repo BackfillRepository, batchSize int32) (BackfillCounts, error) {
	var c BackfillCounts
	after := pgtype.UUID{Valid: true}
	for {
		ids, err := repo.ListSBOMIDsWithLicenseExpressionsPage(ctx, repository.ListSBOMIDsWithLicenseExpressionsPageParams{After: after, RowLimit: batchSize})
		if err != nil {
			return c, fmt.Errorf("listing SBOMs with license expressions: %w", err)
		}
		for _, id := range ids {
			if err := backfillSBOMLicenseExpressions(ctx, repo, id, &c); err != nil {
				return c, err
			}
		}
		if len(ids) < int(batchSize) {
			return c, nil
		}
		after = ids[len(ids)-1]
	}
}

func backfillSBOMLicenseExpressions(ctx context.Context, repo BackfillRepository, sbomID pgtype.UUID, c *BackfillCounts) error {
	sbom, err := repo.GetSBOMRawBomForBackfill(ctx, sbomID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // deleted since it was listed
	}
	if err != nil {
		return fmt.Errorf("reading SBOM %s: %w", uuidToStr(sbomID), err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(sbom.RawBom), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		slog.Warn("backfill license expressions: skipping SBOM, raw_bom decode error", "sbomID", uuidToStr(sbomID), "err", err)
		c.Errored++
		return nil
	}
	refs, err := repo.ListSBOMComponentRefs(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("listing SBOM %s components: %w", uuidToStr(sbomID), err)
	}
	l := expressionLinker{repo: repo, c: c, byRef: make(map[string]pgtype.UUID, len(refs)), licenseIDs: map[string]pgtype.UUID{}}
	for _, r := range refs {
		l.byRef[r.BomRef.String] = r.ID
	}
	if bom.Components == nil {
		return nil
	}
	return l.walk(ctx, *bom.Components)
}

// expressionLinker adds the licenses one SBOM's expression choices name,
// caching each license's id for the rest of the SBOM.
type expressionLinker struct {
	repo       BackfillRepository
	c          *BackfillCounts
	byRef      map[string]pgtype.UUID // component bom-ref → row id
	licenseIDs map[string]pgtype.UUID // licenseKey → license id
}

func (l *expressionLinker) walk(ctx context.Context, comps []cdx.Component) error {
	for i := range comps {
		comp := &comps[i]
		if comp.Components != nil {
			if err := l.walk(ctx, *comp.Components); err != nil {
				return err
			}
		}
		if comp.Licenses == nil {
			continue
		}
		for _, choice := range *comp.Licenses {
			if choice.Expression == "" {
				continue
			}
			componentID, ok := l.byRef[comp.BOMRef]
			if !ok || comp.BOMRef == "" {
				l.c.Skipped++
				continue
			}
			if err := l.link(ctx, componentID, choice.Expression); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *expressionLinker) link(ctx context.Context, componentID pgtype.UUID, expression string) error {
	for _, def := range ExpandLicense("", "", expression) {
		key := licenseKey(def.spdxID, def.name)
		licenseID, ok := l.licenseIDs[key]
		if !ok {
			var err error
			if licenseID, err = upsertLicense(ctx, l.repo, def.spdxID, def.name, ""); err != nil {
				return err
			}
			l.licenseIDs[key] = licenseID
		}
		n, err := l.repo.InsertComponentLicenseIfMissing(ctx, repository.InsertComponentLicenseIfMissingParams{
			ComponentID: componentID,
			LicenseID:   licenseID,
		})
		if err != nil {
			return fmt.Errorf("linking component %s: %w", uuidToStr(componentID), err)
		}
		l.c.Updated += int(n)
	}
	return nil
}
