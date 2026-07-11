// backfill-provenance sets component provenance columns (layer_id, found_by,
// source_package, source_version, source_purl) for rows ingested before
// provenance extraction was added (pre-ocidex-5ur.2), by re-deriving them
// from the SBOM's stored raw_bom.
// Idempotent: only processes components where all five columns are NULL.
// Usage: DATABASE_URL=... backfill-provenance
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/service"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL must be set")
	}

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	q := repository.New(conn)

	sboms, err := q.ListSBOMsWithMissingProvenance(ctx)
	if err != nil {
		return fmt.Errorf("list sboms: %w", err)
	}

	if len(sboms) == 0 {
		slog.Info("backfill-provenance: no rows need backfilling")
		return nil
	}

	sbomCount := len(sboms)
	slog.Info("backfill-provenance: starting", "sboms", sbomCount) //nolint:gosec // sbomCount is len(sboms), not user input

	updated := 0
	errored := 0
	for _, sbom := range sboms {
		components, err := q.ListSBOMComponentsMissingProvenance(ctx, sbom.ID)
		if err != nil {
			slog.Warn("backfill-provenance: skipping SBOM — list components error", "sbomID", sbom.ID, "err", err)
			errored++
			continue
		}
		if len(components) == 0 {
			continue
		}

		existing := make([]service.ExistingComponentRef, len(components))
		for i, c := range components {
			existing[i] = service.ExistingComponentRef{ID: c.ID, BOMRef: c.BomRef.String, Purl: c.Purl.String}
		}

		updates, err := service.ComputeProvenanceUpdates(sbom.RawBom, sbom.Flavor.String, existing)
		if err != nil {
			slog.Warn("backfill-provenance: skipping SBOM — BOM decode error", "sbomID", sbom.ID, "err", err)
			errored++
			continue
		}

		for _, u := range updates {
			if err := q.UpdateComponentProvenance(ctx, repository.UpdateComponentProvenanceParams{
				ID:            u.ComponentID,
				LayerID:       u.LayerID,
				FoundBy:       u.FoundBy,
				SourcePackage: u.SourcePackage,
				SourceVersion: u.SourceVersion,
				SourcePurl:    u.SourcePurl,
			}); err != nil {
				slog.Warn("backfill-provenance: skipping component — update error", "componentID", u.ComponentID, "err", err)
				errored++
				continue
			}
			updated++
		}
	}

	slog.Info("backfill-provenance: done", "updated", updated, "errored", errored)
	return nil
}
