package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// DBPinger is satisfied by *pgxpool.Pool.
type DBPinger interface {
	Ping(ctx context.Context) error
}

// ScanSubmitter is implemented by *scanner.Dispatcher.
type ScanSubmitter interface {
	Submit(req scanner.ScanRequest)
}

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	sbomService       service.SBOMService
	searchService     service.SearchService
	db                DBPinger
	api               huma.API
	scannerDispatcher ScanSubmitter
	webhookSecret     string
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(sbomSvc service.SBOMService, searchSvc service.SearchService, db DBPinger, sc ScanSubmitter, webhookSecret string) *Handler {
	return &Handler{
		sbomService:       sbomSvc,
		searchService:     searchSvc,
		db:                db,
		scannerDispatcher: sc,
		webhookSecret:     webhookSecret,
	}
}

// API returns the huma API instance. This is available after NewRouter has been
// called and is used by the specgen command to export the OpenAPI spec.
func (h *Handler) API() huma.API {
	return h.api
}
