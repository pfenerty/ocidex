// backfill-component-purl splices a component's version into its purl for rows
// whose purl was stored without one, applying the same rule ingestion applies
// (service.ComponentPurlWithVersion).
//
// It exists because the vulnerability store is keyed entirely by purl and OSV
// matches versions server-side: a purl with no version matches nothing and is
// skipped by vuln.queryablePurls, so the component is never scanned. Go main
// modules are the common case — Syft reports them as "(devel)" and ocidex
// recovers the version from the image tag into component.version, which before
// this left the purl bare.
//
// Idempotent: a row whose purl already carries a version is not selected, and a
// row the rule leaves unchanged is not written.
// Usage: DATABASE_URL=... backfill-component-purl
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

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

	rows, err := q.ListComponentsWithUnversionedPurl(ctx)
	if err != nil {
		return fmt.Errorf("list components: %w", err)
	}
	if len(rows) == 0 {
		slog.Info("backfill-component-purl: no rows need backfilling")
		return nil
	}

	rowCount := len(rows)
	slog.Info("backfill-component-purl: starting", "candidates", rowCount) //nolint:gosec // rowCount is len(rows), not user input

	updated, skipped, errored := 0, 0, 0
	for _, row := range rows {
		next := service.ComponentPurlWithVersion(row.Purl.String, row.Version.String)
		if next == row.Purl.String {
			// The rule declined this row (an unparseable purl, say). The SQL
			// predicate is deliberately looser than the rule, so this is
			// expected rather than an error.
			skipped++
			continue
		}
		if err := q.UpdateComponentPurl(ctx, repository.UpdateComponentPurlParams{
			ID:   row.ID,
			Purl: pgtype.Text{String: next, Valid: true},
		}); err != nil {
			slog.Warn("backfill-component-purl: skipping component — update error",
				"componentID", row.ID, "purl", row.Purl.String, "err", err)
			errored++
			continue
		}
		updated++
	}

	slog.Info("backfill-component-purl: done", "updated", updated, "skipped", skipped, "errored", errored)
	return nil
}
