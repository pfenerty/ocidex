package main

import (
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/names"
	"github.com/pfenerty/ocidex/internal/enrichment/provenance"
	"github.com/pfenerty/ocidex/internal/service"
	enrichmentworker "github.com/pfenerty/ocidex/internal/worker/enrichment"
)

func main() {
	if err := enrichmentworker.Run(buildEnrichers, enrichmentworker.RunConfig{
		EnricherName: names.Provenance,
		HintDurable:  "enrich-hint-provenance",
	}); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func buildEnrichers(pool *pgxpool.Pool, appCfg *config.Config) []enrichment.Enricher {
	registrySvc := service.NewRegistryService(pool)
	insecureResolver := service.BuildInsecureHostLookup(registrySvc)
	trustResolver := service.BuildTrustLookup(registrySvc)
	credResolver := service.BuildCredentialLookup(registrySvc)
	return []enrichment.Enricher{
		provenance.NewEnricher(
			provenance.WithInsecureResolver(insecureResolver),
			provenance.WithTrustResolver(trustResolver),
			provenance.WithCredentialResolver(credResolver),
			provenance.WithMaxLayerBytes(appCfg.ProvenanceMaxLayerBytes),
			provenance.WithTimeout(appCfg.ProvenanceTimeout),
		),
	}
}
