package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gorilla/securecookie"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// DBPinger is satisfied by *pgxpool.Pool.
type DBPinger interface {
	Ping(ctx context.Context) error
}

// ScanSubmitter is implemented by *scanner.Dispatcher and *scanner.NATSSubmitter.
type ScanSubmitter interface {
	Submit(req scanner.ScanRequest)
}

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	sbomService     service.SBOMService
	searchService   service.SearchService
	authService     service.AuthService
	registryService service.RegistryService
	db              DBPinger
	api             huma.API
	scanSubmitter   ScanSubmitter
	cfg             *config.Config
	stateCookie     *securecookie.SecureCookie
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(sbomSvc service.SBOMService, searchSvc service.SearchService, authSvc service.AuthService, registrySvc service.RegistryService, db DBPinger, sc ScanSubmitter, cfg *config.Config) *Handler {
	var sc2 *securecookie.SecureCookie
	if cfg != nil {
		sc2 = securecookie.New([]byte(cfg.SessionSecret), nil)
	}
	return &Handler{
		sbomService:     sbomSvc,
		searchService:   searchSvc,
		authService:     authSvc,
		registryService: registrySvc,
		db:              db,
		scanSubmitter:   sc,
		cfg:             cfg,
		stateCookie:     sc2,
	}
}

// API returns the huma API instance. This is available after NewRouter has been
// called and is used by the specgen command to export the OpenAPI spec.
func (h *Handler) API() huma.API {
	return h.api
}
