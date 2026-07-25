package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/enrichment"
	"github.com/pfenerty/ocidex/internal/enrichment/provenance"
	"github.com/pfenerty/ocidex/internal/service"
	enrichmentworker "github.com/pfenerty/ocidex/internal/worker/enrichment"
)

func main() {
	if err := enrichmentworker.Run(buildEnrichers, enrichmentworker.RunConfig{
		EnricherName: "provenance",
		HintDurable:  "enrich-hint-provenance",
	}); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func buildEnrichers(pool *pgxpool.Pool) []enrichment.Enricher {
	registrySvc := service.NewRegistryService(pool)
	insecureResolver := service.BuildInsecureHostLookup(registrySvc)
	trustResolver := service.BuildTrustLookup(registrySvc)
	credResolver := service.BuildCredentialLookup(registrySvc)
	return []enrichment.Enricher{
		provenance.NewEnricher(
			provenance.WithInsecureResolver(insecureResolver),
			provenance.WithTrustResolver(adaptTrustResolver(trustResolver)),
			provenance.WithCredentialResolver(credResolver),
		),
	}
}

// adaptTrustResolver adapts service.TrustConfig to provenance.TrustConfig. The two
// types can't be unified without an import cycle: internal/enrichment (which
// internal/enrichment/provenance depends on for enrichment.SubjectRef) already
// imports internal/service.
func adaptTrustResolver(resolve func(ctx context.Context, host string) service.TrustConfig) provenance.TrustResolver {
	return func(ctx context.Context, host string) provenance.TrustConfig {
		cfg := resolve(ctx, host)
		return provenance.TrustConfig{
			Mode:         cfg.Mode,
			PublicKeyPEM: cfg.PublicKeyPEM,
			Identity:     cfg.Identity,
			Issuer:       cfg.Issuer,
		}
	}
}
