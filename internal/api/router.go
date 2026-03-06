package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

const maxSBOMBodyBytes int64 = 10 << 20 // 10 MB

// NewRouter creates and configures the chi router with huma API registration.
// corsOrigins is a comma-separated list of allowed origins (e.g. "*" or "http://localhost:3000,https://app.example.com").
// apiBaseURL, when non-empty, is added to the OpenAPI servers block so clients know where to reach the API.
func NewRouter(h *Handler, corsOrigins, apiBaseURL string) chi.Router {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(SlogLogger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   parseCORSOrigins(corsOrigins),
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(Authenticate(h.authService))
	r.Use(middleware.Timeout(30 * time.Second))

	config := huma.DefaultConfig("OCIDex API", "1.0.0")
	config.Info.Description = "Open Container Initiative Dex — SBOM metadata management service"

	// Security schemes: Bearer API key or session cookie.
	if config.Components == nil {
		config.Components = &huma.Components{}
	}
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "ocidex_<token>",
			Description:  "API key issued via POST /api/v1/auth/keys",
		},
		"cookieAuth": {
			Type:        "apiKey",
			In:          "cookie",
			Name:        sessionCookieName,
			Description: "Session cookie obtained via GitHub OAuth (/auth/login)",
		},
	}
	// Global security: any request must satisfy bearerAuth OR cookieAuth.
	config.Security = []map[string][]string{
		{"bearerAuth": {}},
		{"cookieAuth": {}},
	}

	if apiBaseURL != "" {
		config.Servers = []*huma.Server{{URL: apiBaseURL, Description: "OCIDex API"}}
	}

	api := humachi.New(r, config)

	h.api = api

	registerHealthOps(api, h)
	registerVersionOps(api, h)
	registerSBOMOps(api, h)
	registerComponentOps(api, h)
	registerLicenseOps(api, h)
	registerArtifactOps(api, h)
	registerDiffOps(api, h)
	registerWebhookOps(api, h)
	registerRegistryOps(api, h)
	registerStatsOps(api, h)
	registerAuthOps(r, api, h)

	return r
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func registerHealthOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "health-check",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Liveness check",
		Tags:        []string{"Health"},
		Security:    []map[string][]string{},
	}, h.HealthCheck)

	huma.Register(api, huma.Operation{
		OperationID: "readiness-check",
		Method:      http.MethodGet,
		Path:        "/ready",
		Summary:     "Readiness check",
		Description: "Verifies the database is reachable.",
		Tags:        []string{"Health"},
		Security:    []map[string][]string{},
	}, h.ReadinessCheck)
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

func registerVersionOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "api-version",
		Method:      http.MethodGet,
		Path:        "/api/v1/",
		Summary:     "API version",
		Tags:        []string{"Meta"},
		Security:    []map[string][]string{},
	}, h.APIVersion)
}

// ---------------------------------------------------------------------------
// SBOM
// ---------------------------------------------------------------------------

func registerSBOMOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID:   "ingest-sbom",
		Method:        http.MethodPost,
		Path:          "/api/v1/sbom",
		Summary:       "Ingest an SBOM",
		Description:   "Accepts a CycloneDX JSON SBOM, validates it, and persists it.",
		Tags:          []string{"SBOMs"},
		MaxBodyBytes:  maxSBOMBodyBytes,
		DefaultStatus: http.StatusCreated,
	}, h.IngestSBOM)

	huma.Register(api, huma.Operation{
		OperationID: "list-sboms",
		Method:      http.MethodGet,
		Path:        "/api/v1/sbom",
		Summary:     "List SBOMs",
		Tags:        []string{"SBOMs"},
	}, h.ListSBOMs)

	huma.Register(api, huma.Operation{
		OperationID: "list-sboms-by-digest",
		Method:      http.MethodGet,
		Path:        "/api/v1/sbom/by-digest/{digest}",
		Summary:     "List SBOMs by image digest",
		Tags:        []string{"SBOMs"},
	}, h.ListSBOMsByDigest)

	huma.Register(api, huma.Operation{
		OperationID: "get-sbom",
		Method:      http.MethodGet,
		Path:        "/api/v1/sbom/{id}",
		Summary:     "Get an SBOM",
		Tags:        []string{"SBOMs"},
	}, h.GetSBOM)

	huma.Register(api, huma.Operation{
		OperationID: "get-sbom-dependencies",
		Method:      http.MethodGet,
		Path:        "/api/v1/sbom/{id}/dependencies",
		Summary:     "Get SBOM dependency graph",
		Tags:        []string{"SBOMs"},
	}, h.GetSBOMDependencies)

	huma.Register(api, huma.Operation{
		OperationID: "list-sbom-components",
		Method:      http.MethodGet,
		Path:        "/api/v1/sbom/{id}/components",
		Summary:     "List components in an SBOM",
		Tags:        []string{"SBOMs"},
	}, h.ListSBOMComponents)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-sbom",
		Method:        http.MethodDelete,
		Path:          "/api/v1/sbom/{id}",
		Summary:       "Delete an SBOM",
		Tags:          []string{"SBOMs"},
		DefaultStatus: http.StatusNoContent,
	}, h.DeleteSBOM)
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

func registerComponentOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "search-components",
		Method:      http.MethodGet,
		Path:        "/api/v1/components",
		Summary:     "Search components",
		Tags:        []string{"Components"},
	}, h.SearchComponents)

	huma.Register(api, huma.Operation{
		OperationID: "search-distinct-components",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/distinct",
		Summary:     "Search distinct components",
		Tags:        []string{"Components"},
	}, h.SearchDistinctComponents)

	huma.Register(api, huma.Operation{
		OperationID: "list-component-purl-types",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/purl-types",
		Summary:     "List component PURL types",
		Tags:        []string{"Components"},
	}, h.ListComponentPurlTypes)

	huma.Register(api, huma.Operation{
		OperationID: "get-component-versions",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/versions",
		Summary:     "Get component versions",
		Tags:        []string{"Components"},
	}, h.GetComponentVersions)

	huma.Register(api, huma.Operation{
		OperationID: "get-component",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/{id}",
		Summary:     "Get a component",
		Tags:        []string{"Components"},
	}, h.GetComponent)
}

// ---------------------------------------------------------------------------
// Licenses
// ---------------------------------------------------------------------------

func registerLicenseOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-licenses",
		Method:      http.MethodGet,
		Path:        "/api/v1/licenses",
		Summary:     "List licenses",
		Tags:        []string{"Licenses"},
	}, h.ListLicenses)

	huma.Register(api, huma.Operation{
		OperationID: "list-components-by-license",
		Method:      http.MethodGet,
		Path:        "/api/v1/licenses/{id}/components",
		Summary:     "List components by license",
		Tags:        []string{"Licenses"},
	}, h.ListComponentsByLicense)
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

func registerArtifactOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-artifacts",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts",
		Summary:     "List artifacts",
		Tags:        []string{"Artifacts"},
	}, h.ListArtifacts)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}",
		Summary:     "Get an artifact",
		Tags:        []string{"Artifacts"},
	}, h.GetArtifact)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-artifact",
		Method:        http.MethodDelete,
		Path:          "/api/v1/artifacts/{id}",
		Summary:       "Delete an artifact",
		Tags:          []string{"Artifacts"},
		DefaultStatus: http.StatusNoContent,
	}, h.DeleteArtifact)

	huma.Register(api, huma.Operation{
		OperationID: "list-artifact-sboms",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/sboms",
		Summary:     "List SBOMs for an artifact",
		Tags:        []string{"Artifacts"},
	}, h.ListArtifactSBOMs)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact-changelog",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/changelog",
		Summary:     "Get artifact changelog",
		Tags:        []string{"Artifacts"},
	}, h.GetArtifactChangelog)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact-license-summary",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/license-summary",
		Summary:     "Get artifact license summary",
		Tags:        []string{"Artifacts"},
	}, h.GetArtifactLicenseSummary)
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

func registerDiffOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "diff-sboms",
		Method:      http.MethodGet,
		Path:        "/api/v1/diff",
		Summary:     "Diff two SBOMs",
		Description: "Computes the component diff between two SBOMs.",
		Tags:        []string{"Diff"},
	}, h.DiffSBOMs)
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

func registerWebhookOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID:   "registry-webhook",
		Method:        http.MethodPost,
		Path:          "/api/v1/webhooks/{registryID}",
		Summary:       "Receive registry push notifications",
		Tags:          []string{"Webhooks"},
		MaxBodyBytes:  64 * 1024,
		DefaultStatus: http.StatusAccepted,
		Security:      []map[string][]string{},
	}, h.HandleRegistryWebhook)
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

func registerRegistryOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID:   "test-registry-connection",
		Method:        http.MethodPost,
		Path:          "/api/v1/registries/test-connection",
		Summary:       "Test registry connectivity",
		Description:   "Probes the registry's /v2/ endpoint and reports whether it is reachable.",
		Tags:          []string{"Registries"},
		DefaultStatus: http.StatusOK,
	}, h.TestRegistryConnection)

	huma.Register(api, huma.Operation{
		OperationID: "list-registries",
		Method:      http.MethodGet,
		Path:        "/api/v1/registries",
		Summary:     "List registries",
		Tags:        []string{"Registries"},
	}, h.ListRegistries)

	huma.Register(api, huma.Operation{
		OperationID:   "create-registry",
		Method:        http.MethodPost,
		Path:          "/api/v1/registries",
		Summary:       "Create a registry",
		Tags:          []string{"Registries"},
		DefaultStatus: http.StatusCreated,
	}, h.CreateRegistry)

	huma.Register(api, huma.Operation{
		OperationID: "get-registry",
		Method:      http.MethodGet,
		Path:        "/api/v1/registries/{id}",
		Summary:     "Get a registry",
		Tags:        []string{"Registries"},
	}, h.GetRegistry)

	huma.Register(api, huma.Operation{
		OperationID: "update-registry",
		Method:      http.MethodPut,
		Path:        "/api/v1/registries/{id}",
		Summary:     "Update a registry",
		Tags:        []string{"Registries"},
	}, h.UpdateRegistry)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-registry",
		Method:        http.MethodDelete,
		Path:          "/api/v1/registries/{id}",
		Summary:       "Delete a registry",
		Tags:          []string{"Registries"},
		DefaultStatus: http.StatusNoContent,
	}, h.DeleteRegistry)

	huma.Register(api, huma.Operation{
		OperationID:   "scan-registry",
		Method:        http.MethodPost,
		Path:          "/api/v1/registries/{id}/scan",
		Summary:       "Trigger ad-hoc registry scan",
		Description:   "Walks the registry catalog, filters by configured patterns, and queues scan requests for all matching images.",
		Tags:          []string{"Registries"},
		DefaultStatus: http.StatusAccepted,
	}, h.ScanRegistry)
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

func registerStatsOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-dashboard-stats",
		Method:      http.MethodGet,
		Path:        "/api/v1/stats/summary",
		Summary:     "Get dashboard summary statistics",
		Tags:        []string{"Stats"},
	}, h.GetDashboardStats)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseCORSOrigins splits a comma-separated origins string into a slice.
func parseCORSOrigins(raw string) []string {
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			origins = append(origins, s)
		}
	}
	if len(origins) == 0 {
		return []string{"*"}
	}
	return origins
}
