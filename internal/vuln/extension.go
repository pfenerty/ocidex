package vuln

import (
	"context"
	"log/slog"
	"time"

	"github.com/pfenerty/ocidex/internal/event"
)

// IngestVulnExtension subscribes to SBOMIngested and immediately queries OSV
// for any component purls from the new SBOM that are not yet in
// package_vulnerability, shrinking the gap before the next scheduled refresh.
type IngestVulnExtension struct {
	store     Store
	refresher *RefreshService
	logger    *slog.Logger
	enabled   bool
	sem       chan struct{}
}

// NewIngestVulnExtension constructs an IngestVulnExtension. maxConcurrency caps
// how many OSV lookups can run at once; values below 1 are treated as 1.
func NewIngestVulnExtension(store Store, refresher *RefreshService, logger *slog.Logger, enabled bool, maxConcurrency int) *IngestVulnExtension {
	if logger == nil {
		logger = slog.Default()
	}
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	return &IngestVulnExtension{
		store:     store,
		refresher: refresher,
		logger:    logger,
		enabled:   enabled,
		sem:       make(chan struct{}, maxConcurrency),
	}
}

func (e *IngestVulnExtension) Name() string { return "vuln-ingest-lookup" }

// Init subscribes to SBOMIngested. Each event spawns a goroutine that queries
// OSV for unknown purls; errors are logged and never propagate to the caller.
func (e *IngestVulnExtension) Init(bus *event.Bus) error {
	if !e.enabled {
		return nil
	}
	bus.Subscribe(event.SBOMIngested, func(_ context.Context, evt event.Event) {
		data, ok := evt.Data.(event.SBOMIngestedData)
		if !ok {
			return
		}
		go func() { //nolint:gosec // G118: intentionally fresh context — goroutine outlives the event handler
			e.sem <- struct{}{}
			defer func() { <-e.sem }()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			purls, err := e.store.ListUnknownPurlsForSBOM(ctx, data.SBOMID)
			if err != nil {
				e.logger.Warn("vuln ingest-lookup: listing unknown purls failed",
					"sbom_id", data.SBOMID, "err", err)
				return
			}
			if len(purls) == 0 {
				return
			}
			if err := e.refresher.LookupPurls(ctx, purls); err != nil {
				e.logger.Warn("vuln ingest-lookup: lookup failed",
					"sbom_id", data.SBOMID, "purls", len(purls), "err", err)
				return
			}
			e.logger.Info("vuln ingest-lookup: complete",
				"sbom_id", data.SBOMID, "purls", len(purls))
		}()
	})
	return nil
}

func (e *IngestVulnExtension) Start(_ context.Context) error { return nil }
func (e *IngestVulnExtension) Stop() error                   { return nil }
