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

	"github.com/pfenerty/ocidex/internal/enrichment/names"
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

	licenseUpserter
	ListNameOnlyLicensesPage(ctx context.Context, arg repository.ListNameOnlyLicensesPageParams) ([]repository.ListNameOnlyLicensesPageRow, error)
	CopyLicenseLinks(ctx context.Context, arg repository.CopyLicenseLinksParams) error
	DeleteLicenseByID(ctx context.Context, id pgtype.UUID) error
	ListSBOMIDsWithLicenseExpressionsPage(ctx context.Context, arg repository.ListSBOMIDsWithLicenseExpressionsPageParams) ([]pgtype.UUID, error)
	ListSBOMComponentRefs(ctx context.Context, sbomID pgtype.UUID) ([]repository.ListSBOMComponentRefsRow, error)
	InsertComponentLicenseIfMissing(ctx context.Context, arg repository.InsertComponentLicenseIfMissingParams) (int64, error)

	ListSBOMsMissingRootEnrichmentPage(ctx context.Context, arg repository.ListSBOMsMissingRootEnrichmentPageParams) ([]repository.ListSBOMsMissingRootEnrichmentPageRow, error)
	InsertEnrichmentJob(ctx context.Context, arg repository.InsertEnrichmentJobParams) (repository.EnrichmentJob, error)
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
	// LicenseNames counts name-only licenses re-derived with ExpandLicense:
	// Updated is rewritten (split, aliased, merged or dropped), Skipped kept.
	LicenseNames BackfillCounts
	// LicenseExpressions counts SBOMs whose CycloneDX license expressions were
	// read; Updated is component links added.
	LicenseExpressions BackfillCounts
	// RootEnrichment counts SBOMs that had a root enricher neither enqueued nor
	// run: Updated is SBOMs whose missing jobs were enqueued.
	RootEnrichment BackfillCounts
}

// BackfillBatches sizes each backfill step's pages.
//
// The steps cost different things per page. SBOMs bounds the raw_bom read at
// once by the flavor and provenance steps. Components is the purl step's page,
// whose rows are three short columns: its predicate has no index, so every
// page is a scan of the component table, and a small page multiplies that
// scan by the number of pages.
type BackfillBatches struct {
	SBOMs      int32
	Components int32
}

// Backfill derives the columns that ingest now writes for rows stored before
// it did: an SBOM's flavor, a component's versioned purl and its provenance
// (ADR-034, ADR-048), and licenses as ExpandLicense derives them. Each value is re-derived from data already in the row
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
	if res.Provenance, err = backfillProvenance(ctx, repo, batches.SBOMs); err != nil {
		return res, err
	}
	if res.LicenseNames, err = backfillLicenseNames(ctx, repo, batches.SBOMs); err != nil {
		return res, err
	}
	if res.LicenseExpressions, err = backfillLicenseExpressions(ctx, repo, batches.SBOMs); err != nil {
		return res, err
	}
	res.RootEnrichment, err = backfillRootEnrichment(ctx, repo, batches.SBOMs)
	return res, err
}

// backfillRootEnrichment enqueues the root enrichers' jobs for SBOMs that have
// neither a job nor a result for one of them. Ingest used to enqueue those jobs
// after commit and could lose them, and a re-upload short-circuits on the
// digest, so nothing else would ever enrich such an SBOM. Ingest now enqueues
// them in its own transaction, so new orphans cannot appear.
// The job's architecture and build date are re-derived from raw_bom, as ingest
// does when its caller declares none.
func backfillRootEnrichment(ctx context.Context, repo BackfillRepository, batchSize int32) (BackfillCounts, error) {
	var c BackfillCounts
	after := pgtype.UUID{Valid: true}
	for {
		rows, err := repo.ListSBOMsMissingRootEnrichmentPage(ctx, repository.ListSBOMsMissingRootEnrichmentPageParams{
			Enrichers: names.Roots(), After: after, RowLimit: batchSize,
		})
		if err != nil {
			return c, fmt.Errorf("listing SBOMs missing root enrichment: %w", err)
		}
		for _, row := range rows {
			if err := backfillSBOMRootEnrichment(ctx, repo, row, &c); err != nil {
				return c, err
			}
		}
		if len(rows) < int(batchSize) {
			return c, nil
		}
		after = rows[len(rows)-1].ID
	}
}

func backfillSBOMRootEnrichment(ctx context.Context, repo BackfillRepository, row repository.ListSBOMsMissingRootEnrichmentPageRow, c *BackfillCounts) error {
	sbom, err := repo.GetSBOMRawBomForBackfill(ctx, row.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // deleted since it was listed
	}
	if err != nil {
		return fmt.Errorf("reading SBOM %s: %w", row.ID.String(), err)
	}
	// An undecodable BOM still gets its jobs, without architecture or build
	// date: the enrichers read the image, not the BOM.
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(sbom.RawBom), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		slog.Warn("backfill root enrichment: raw_bom decode error; enqueueing without architecture/build date",
			"sbomID", row.ID.String(), "err", err)
	}
	arch, bd := resolveArchitecture(&bom, IngestParams{}), resolveBuildDate(&bom, IngestParams{})
	for _, name := range row.Missing {
		_, err := repo.InsertEnrichmentJob(ctx, enrichJobParams(ctx, row.ID, arch, bd, name))
		if err != nil && !isUniqueViolation(err) { // a unique violation: enqueued since listed
			return fmt.Errorf("enqueueing %s enrichment for SBOM %s: %w", name, row.ID.String(), err)
		}
	}
	c.Updated++
	return nil
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
				slog.Warn("backfill flavor: skipping SBOM, raw_bom decode error", "sbomID", row.ID.String(), "err", err)
				c.Errored++
				continue
			}
			flavor := DetectFlavor(&bom, row.SubjectVersion.String)
			if err := repo.UpdateSBOMFlavor(ctx, repository.UpdateSBOMFlavorParams{
				ID:     row.ID,
				Flavor: pgtype.Text{String: flavor, Valid: true},
			}); err != nil {
				return c, fmt.Errorf("updating SBOM %s flavor: %w", row.ID.String(), err)
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
				return c, fmt.Errorf("updating component %s purl: %w", row.ID.String(), err)
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
		return fmt.Errorf("reading SBOM %s: %w", sbomID.String(), err)
	}
	components, err := repo.ListSBOMComponentsMissingProvenance(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("listing SBOM %s components: %w", sbomID.String(), err)
	}
	existing := make([]ExistingComponentRef, len(components))
	for i, comp := range components {
		existing[i] = ExistingComponentRef{ID: comp.ID, BOMRef: comp.BomRef.String, Purl: comp.Purl.String}
	}
	updates, err := ComputeProvenanceUpdates(sbom.RawBom, sbom.Flavor.String, existing)
	if err != nil {
		slog.Warn("backfill provenance: skipping SBOM, raw_bom decode error", "sbomID", sbomID.String(), "err", err)
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
			return fmt.Errorf("updating component %s provenance: %w", u.ComponentID.String(), err)
		}
		c.Updated++
	}
	return nil
}
