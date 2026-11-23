package api

import (
	"context"
	"net/http"

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
	sbomQueries      SBOMReader
	components       ComponentReader
	artifacts        ArtifactReader
	artifactInsights ArtifactInsights
	insights         InsightReader
	authenticator    Authenticator
	logins           LoginFlow
	accounts         AccountAdmin
	registryService  RegistryStore
	namespaceService service.NamespaceService
	sourceService    service.SourceService
	jobService       JobAdmin
	enrichJobService service.EnrichJobService
	watchService     service.WatchService
	clusters         ClusterAdmin
	clusterAgents    ClusterAgent
	clusterInventory ClusterInventory
	db               DBPinger
	api              huma.API
	scanSubmitter    ScanSubmitter
	adhocWalks       *scanner.AdhocWalks
	clusterIngests   *scanner.AdhocWalks
	cfg              *config.Config
	stateCookie      *securecookie.SecureCookie
	clientIPs        *ClientIPResolver
	ingestLimit      *rateLimiter
	heavyLimit       *rateLimiter
	meterProvider    metric.MeterProvider
	tracerProvider   trace.TracerProvider
	approvals        service.ApprovalService
	// router is the built router, which an approved action's stored request
	// is replayed through. Set by NewRouter.
	router http.Handler
}

// Deps is what a Handler is built from. Fields are named, so
// two dependencies of the same kind can't be swapped by position, and each is
// a consumer-sized view (deps.go): a test sets only the ones its routes use.
// cmd/ocidex hands one service to every view of it, e.g. the search service to
// SBOMQueries, Components, Artifacts, ArtifactInsights and Insights.
type Deps struct {
	SBOMs            service.SBOMService
	SBOMQueries      SBOMReader
	Components       ComponentReader
	Artifacts        ArtifactReader
	ArtifactInsights ArtifactInsights
	Insights         InsightReader
	Authenticator    Authenticator
	Logins           LoginFlow
	Accounts         AccountAdmin
	Registries       RegistryStore
	Namespaces       service.NamespaceService
	Sources          service.SourceService
	Jobs             JobAdmin
	EnrichJobs       service.EnrichJobService
	Watches          service.WatchService
	Clusters         ClusterAdmin
	ClusterAgents    ClusterAgent
	ClusterInventory ClusterInventory
	DB               DBPinger
	Scans            ScanSubmitter
	Config           *config.Config
	Approvals        service.ApprovalService
}

// NewHandler creates a new Handler from its dependencies.
func NewHandler(d Deps) *Handler {
	var sc2 *securecookie.SecureCookie
	var clientIPs ClientIPPolicy
	if d.Config != nil {
		sc2 = securecookie.New([]byte(d.Config.SessionSecret), nil)
		clientIPs = ClientIPPolicy{
			TrustedProxies: d.Config.TrustedProxies,
			TrustedHops:    d.Config.TrustedProxyHops,
			Header:         d.Config.ClientIPHeader,
		}
	}
	return &Handler{
		sbomService:      d.SBOMs,
		sbomQueries:      d.SBOMQueries,
		components:       d.Components,
		artifacts:        d.Artifacts,
		artifactInsights: d.ArtifactInsights,
		insights:         d.Insights,
		authenticator:    d.Authenticator,
		logins:           d.Logins,
		accounts:         d.Accounts,
		registryService:  d.Registries,
		namespaceService: d.Namespaces,
		sourceService:    d.Sources,
		jobService:       d.Jobs,
		enrichJobService: d.EnrichJobs,
		watchService:     d.Watches,
		clusters:         d.Clusters,
		clusterAgents:    d.ClusterAgents,
		clusterInventory: d.ClusterInventory,
		db:               d.DB,
		scanSubmitter:    d.Scans,
		approvals:        d.Approvals,
		cfg:              d.Config,
		stateCookie:      sc2,
		clientIPs:        NewClientIPResolver(clientIPs),
		meterProvider:    noop.NewMeterProvider(),
		tracerProvider:   tracenoop.NewTracerProvider(),
	}
}

// WithAdhocWalks sets the coordinator that runs ad-hoc registry walks
// (POST /registries/{id}/scan). Without it the route answers 503, as it does
// with no scan submitter.
func (h *Handler) WithAdhocWalks(w *scanner.AdhocWalks) *Handler {
	h.adhocWalks = w
	return h
}

// WithClusterIngests sets the coordinator that runs cluster auto-ingest after
// an inventory snapshot. Without it auto-ingest is skipped.
func (h *Handler) WithClusterIngests(w *scanner.AdhocWalks) *Handler {
	h.clusterIngests = w
	return h
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
