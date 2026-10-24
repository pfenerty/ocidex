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

	"github.com/pfenerty/ocidex/internal/mainmodule"
	"github.com/pfenerty/ocidex/internal/repository"
)

// BackfillRepository is the slice of the repository `ocidex migrate backfill`
// needs.
type BackfillRepository interface {
	ListSBOMsWithoutFlavorPage(ctx context.Context, arg repository.ListSBOMsWithoutFlavorPageParams) ([]repository.ListSBOMsWithoutFlavorPageRow, error)
	UpdateSBOMFlavor(ctx context.Context, arg repository.UpdateSBOMFlavorParams) error
	ListComponentsWithUnversionedPurlPage(ctx context.Context, arg repository.ListComponentsWithUnversionedPurlPageParams) ([]repository.ListComponentsWithUnversionedPurlPageRow, error)
	UpdateComponentPurl(ctx context.Context, arg repository.UpdateComponentPurlParams) error
	ListSBOMIDsWithMissingProvenancePage(ctx context.Context, arg repository.ListSBOMIDsWithMissingProvenancePageParams) ([]pgtype.UUID, error)
	GetSBOMRawBomForBackfill(ctx context.Context, id pgtype.UUID) (repository.GetSBOMRawBomForBackfillRow, error)
	ListSBOMComponentsMissingProvenance(ctx context.Context, sbomID pgtype.UUID) ([]repository.ListSBOMComponentsMissingProvenanceRow, error)
	UpdateComponentProvenance(ctx context.Context, arg repository.UpdateComponentProvenanceParams) error
}

// BackfillCounts counts what one backfill step did.
type BackfillCounts struct {
	Updated int // rows written
	Skipped int // rows selected that the rule left unchanged
	Errored int // rows (or SBOMs) that could not be read or written; logged
}

// BackfillResult counts each step of Backfill.
type BackfillResult struct {
	Flavor     BackfillCounts // sbom.flavor, pre-F2 rows
	Purl       BackfillCounts // component.purl without its version
	Provenance BackfillCounts // component provenance columns and file_path (pre-00072)
}

// BackfillBatches sizes each backfill step's pages.
//
// The steps cost different things per page. SBOMs bounds the raw_bom read at
// once by the flavor and provenance steps. Components is the purl step's page,
// whose rows are three short columns: its predicate has no index, so every
// page is a scan of the component table, and a small page multiplies that
// scan by the number of pages (ocidex-ah9z).
type BackfillBatches struct {
	SBOMs      int32
	Components int32
}

// Backfill derives the columns that ingest now writes for rows stored before
// it did: an SBOM's flavor, a component's versioned purl and its provenance
// (ADR-034, ADR-048). Each value is re-derived from data already in the row
// or its SBOM's raw_bom, so the pass is idempotent and safe to re-run; a fresh
// install has nothing to do. A row that cannot be decoded or written is
// logged and counted, not fatal.
func Backfill(ctx context.Context, repo BackfillRepository, batches BackfillBatches) (BackfillResult, error) {
	var res BackfillResult
	var err error
	if res.Flavor, err = backfillFlavor(ctx, repo, batches.SBOMs); err != nil {
		return res, err
	}
	if res.Purl, err = backfillPurl(ctx, repo, batches.Components); err != nil {
		return res, err
	}
	res.Provenance, err = backfillProvenance(ctx, repo, batches.SBOMs)
	return res, err
}

func backfillFlavor(ctx context.Context, repo BackfillRepository, batchSize int32) (BackfillCounts, error) {
	var c BackfillCounts
	after := pgtype.UUID{Valid: true}
	for {
		rows, err := repo.ListSBOMsWithoutFlavorPage(ctx, repository.ListSBOMsWithoutFlavorPageParams{After: after, RowLimit: batchSize})
		if err != nil {
			return c, fmt.Errorf("listing SBOMs without flavor: %w", err)
		}
		for _, row := range rows {
			var bom cdx.BOM
			if err := cdx.NewBOMDecoder(bytes.NewReader(row.RawBom), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
				slog.Warn("backfill flavor: skipping SBOM, raw_bom decode error", "sbomID", uuidToStr(row.ID), "err", err)
				c.Errored++
				continue
			}
			flavor := DetectFlavor(&bom, row.SubjectVersion.String)
			if err := repo.UpdateSBOMFlavor(ctx, repository.UpdateSBOMFlavorParams{
				ID:     row.ID,
				Flavor: pgtype.Text{String: flavor, Valid: true},
			}); err != nil {
				return c, fmt.Errorf("updating SBOM %s flavor: %w", uuidToStr(row.ID), err)
			}
			c.Updated++
		}
		if len(rows) < int(batchSize) {
			return c, nil
		}
		after = rows[len(rows)-1].ID
	}
}

func backfillPurl(ctx context.Context, repo BackfillRepository, batchSize int32) (BackfillCounts, error) {
	var c BackfillCounts
	after := pgtype.UUID{Valid: true}
	for {
		rows, err := repo.ListComponentsWithUnversionedPurlPage(ctx, repository.ListComponentsWithUnversionedPurlPageParams{After: after, RowLimit: batchSize})
		if err != nil {
			return c, fmt.Errorf("listing components with unversioned purls: %w", err)
		}
		for _, row := range rows {
			next := mainmodule.EffectivePurl(row.Purl.String, row.Version.String)
			if next == row.Purl.String {
				// The rule declined this row (an unparseable purl, say). The SQL
				// predicate is deliberately looser than the rule.
				c.Skipped++
				continue
			}
			if err := repo.UpdateComponentPurl(ctx, repository.UpdateComponentPurlParams{
				ID:   row.ID,
				Purl: pgtype.Text{String: next, Valid: true},
			}); err != nil {
				return c, fmt.Errorf("updating component %s purl: %w", uuidToStr(row.ID), err)
			}
			c.Updated++
		}
		if len(rows) < int(batchSize) {
			return c, nil
		}
		after = rows[len(rows)-1].ID
	}
}

func backfillProvenance(ctx context.Context, repo BackfillRepository, batchSize int32) (BackfillCounts, error) {
	var c BackfillCounts
	after := pgtype.UUID{Valid: true}
	for {
		ids, err := repo.ListSBOMIDsWithMissingProvenancePage(ctx, repository.ListSBOMIDsWithMissingProvenancePageParams{After: after, RowLimit: batchSize})
		if err != nil {
			return c, fmt.Errorf("listing SBOMs with missing provenance: %w", err)
		}
		for _, id := range ids {
			if err := backfillSBOMProvenance(ctx, repo, id, &c); err != nil {
				return c, err
			}
		}
		if len(ids) < int(batchSize) {
			return c, nil
		}
		after = ids[len(ids)-1]
	}
}

// backfillSBOMProvenance re-derives provenance for one SBOM's components
// from its raw_bom. Only database errors are returned; a BOM that cannot be
// decoded is logged and counted.
func backfillSBOMProvenance(ctx context.Context, repo BackfillRepository, sbomID pgtype.UUID, c *BackfillCounts) error {
	sbom, err := repo.GetSBOMRawBomForBackfill(ctx, sbomID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // deleted since it was listed
	}
	if err != nil {
		return fmt.Errorf("reading SBOM %s: %w", uuidToStr(sbomID), err)
	}
	components, err := repo.ListSBOMComponentsMissingProvenance(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("listing SBOM %s components: %w", uuidToStr(sbomID), err)
	}
	existing := make([]ExistingComponentRef, len(components))
	for i, comp := range components {
		existing[i] = ExistingComponentRef{ID: comp.ID, BOMRef: comp.BomRef.String, Purl: comp.Purl.String}
	}
	updates, err := ComputeProvenanceUpdates(sbom.RawBom, sbom.Flavor.String, existing)
	if err != nil {
		slog.Warn("backfill provenance: skipping SBOM, raw_bom decode error", "sbomID", uuidToStr(sbomID), "err", err)
		c.Errored++
		return nil
	}
	c.Skipped += len(existing) - len(updates)
	for _, u := range updates {
		if err := repo.UpdateComponentProvenance(ctx, repository.UpdateComponentProvenanceParams{
			ID:            u.ComponentID,
			LayerID:       u.LayerID,
			FoundBy:       u.FoundBy,
			SourcePackage: u.SourcePackage,
			SourceVersion: u.SourceVersion,
			SourcePurl:    u.SourcePurl,
			FilePath:      u.FilePath,
		}); err != nil {
			return fmt.Errorf("updating component %s provenance: %w", uuidToStr(u.ComponentID), err)
		}
		c.Updated++
	}
	return nil
}
