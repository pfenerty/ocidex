// backfill-flavor sets sbom.flavor for rows where it was not detected at ingest (pre-F2).
// Idempotent: only processes rows where flavor IS NULL or empty.
// Usage: DATABASE_URL=... backfill-flavor
package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

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

	rows, err := q.ListSBOMsWithoutFlavor(ctx)
	if err != nil {
		return fmt.Errorf("list sboms: %w", err)
	}

	if len(rows) == 0 {
		slog.Info("backfill-flavor: no rows need backfilling")
		return nil
	}

	rowCount := len(rows)
	slog.Info("backfill-flavor: starting", "count", rowCount) //nolint:gosec // rowCount is len(rows), not user input

	updated := 0
	errored := 0
	for _, row := range rows {
		flavor, err := parseFlavor(row.RawBom, row.SubjectVersion.String)
		if err != nil {
			slog.Warn("backfill-flavor: skipping row — BOM parse error",
				"id", row.ID, "err", err)
			errored++
			continue
		}
		if err := q.UpdateSBOMFlavor(ctx, repository.UpdateSBOMFlavorParams{
			ID:     row.ID,
			Flavor: pgtype.Text{String: flavor, Valid: true},
		}); err != nil {
			slog.Warn("backfill-flavor: skipping row — update error",
				"id", row.ID, "err", err)
			errored++
			continue
		}
		updated++
	}

	slog.Info("backfill-flavor: done", "updated", updated, "errored", errored)
	return nil
}

func parseFlavor(rawBom []byte, subjectVersion string) (string, error) {
	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(bytes.NewReader(rawBom), cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		return "", err
	}
	return service.DetectFlavor(&bom, subjectVersion), nil
}
