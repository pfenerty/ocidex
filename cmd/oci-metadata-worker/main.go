package main

import (
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/oci"
	"github.com/pfenerty/ocidex/internal/service"
	enrichmentworker "github.com/pfenerty/ocidex/internal/worker/enrichment"
)

func main() {
	if err := enrichmentworker.Run(buildEnrichers, enrichmentworker.RunConfig{
		EnricherName: "oci-metadata",
		HintDurable:  "enrich-hint-oci-metadata",
	}); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func buildEnrichers(pool *pgxpool.Pool) []enrichment.Enricher {
	registrySvc := service.NewRegistryService(pool)
	insecureResolver := service.BuildInsecureHostLookup(registrySvc)
	credResolver := service.BuildCredentialLookup(registrySvc)
	return []enrichment.Enricher{
		oci.NewEnricher(
			oci.WithInsecureResolver(insecureResolver),
			oci.WithCredentialResolver(credResolver),
		),
	}
}
