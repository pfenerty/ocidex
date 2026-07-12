package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/git"
	"github.com/pfenerty/ocidex/internal/enrichment/oci"
	"github.com/pfenerty/ocidex/internal/repository"
	enrichmentworker "github.com/pfenerty/ocidex/internal/worker/enrichment"
)

func main() {
	if err := enrichmentworker.Run(buildEnrichers, enrichmentworker.RunConfig{
		EnricherName: "git",
		HintDurable:  "enrich-hint-git",
	}); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func buildEnrichers(pool *pgxpool.Pool) []enrichment.Enricher {
	store := repository.New(pool)
	ociReader := func(ctx context.Context, sbomID pgtype.UUID) (string, string, error) {
		e, err := store.GetEnrichment(ctx, repository.GetEnrichmentParams{
			SbomID:       sbomID,
			EnricherName: "oci-metadata",
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", nil
		}
		if err != nil {
			return "", "", err
		}
		var meta oci.Metadata
		if err := json.Unmarshal(e.Data, &meta); err != nil {
			return "", "", err
		}
		return meta.SourceURL, meta.Revision, nil
	}

	// TODO: wire a per-host GitHub token resolver once token storage exists;
	// unauthenticated GitHub API access is acceptable for the foundation.
	return []enrichment.Enricher{
		git.NewEnricher(git.WithOCIDataReader(ociReader)),
	}
}
