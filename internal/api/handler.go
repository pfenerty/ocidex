package api

import (
	"context"
	"net/netip"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gorilla/securecookie"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

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
	Submit(ctx context.Context, req scanner.ScanRequest) error
}

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	sbomService      service.SBOMService
	searchService    service.SearchService
	authService      service.AuthService
	registryService  service.RegistryService
	namespaceService service.NamespaceService
	sourceService    service.SourceService
	jobService       service.JobService
	enrichJobService service.EnrichJobService
	watchService     service.WatchService
	clusterService   service.ClusterService
	db               DBPinger
	api              huma.API
	scanSubmitter    ScanSubmitter
	cfg              *config.Config
	stateCookie      *securecookie.SecureCookie
	clientIPs        *ClientIPResolver
	ingestLimit      *rateLimiter
	heavyLimit       *rateLimiter
	meterProvider    metric.MeterProvider
	tracerProvider   trace.TracerProvider
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(sbomSvc service.SBOMService, searchSvc service.SearchService, authSvc service.AuthService, registrySvc service.RegistryService, namespaceSvc service.NamespaceService, sourceSvc service.SourceService, jobSvc service.JobService, enrichJobSvc service.EnrichJobService, watchSvc service.WatchService, clusterSvc service.ClusterService, db DBPinger, sc ScanSubmitter, cfg *config.Config) *Handler {
	var sc2 *securecookie.SecureCookie
	var trustedProxies []netip.Prefix
	if cfg != nil {
		sc2 = securecookie.New([]byte(cfg.SessionSecret), nil)
		trustedProxies = cfg.TrustedProxies
	}
	return &Handler{
		sbomService:      sbomSvc,
		searchService:    searchSvc,
		authService:      authSvc,
		registryService:  registrySvc,
		namespaceService: namespaceSvc,
		sourceService:    sourceSvc,
		jobService:       jobSvc,
		enrichJobService: enrichJobSvc,
		watchService:     watchSvc,
		clusterService:   clusterSvc,
		db:               db,
		scanSubmitter:    sc,
		cfg:              cfg,
		stateCookie:      sc2,
		clientIPs:        NewClientIPResolver(trustedProxies),
		meterProvider:    noop.NewMeterProvider(),
		tracerProvider:   tracenoop.NewTracerProvider(),
	}
}

// WithTracerProvider sets the provider the router records request spans on
// (ADR-0055). Without it they go to a no-op provider. Call it before NewRouter.
func (h *Handler) WithTracerProvider(tp trace.TracerProvider) *Handler {
	h.tracerProvider = tp
	return h
}

// WithMeterProvider sets the provider the router records request metrics on
// (ADR-0054). Without it they go to a no-op provider. Call it before NewRouter.
func (h *Handler) WithMeterProvider(mp metric.MeterProvider) *Handler {
	h.meterProvider = mp
	return h
}

// API returns the huma API instance. This is available after NewRouter has been
// called and is used by the specgen command to export the OpenAPI spec.
func (h *Handler) API() huma.API {
	return h.api
}
