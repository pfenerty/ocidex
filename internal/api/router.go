package api

import (
	"log/slog"
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

// OpenAPI tag labels. Operations are grouped in the generated spec by exact
// string match, so a typo silently splits a group instead of failing a build.
const (
	tagSBOMs      = "SBOMs"
	tagComponents = "Components"
	tagArtifacts  = "Artifacts"
	tagLicenses   = "Licenses"
	tagRegistries = "Registries"
	tagNamespaces = "Namespaces"
	tagSources    = "Sources"
	tagClusters   = "Clusters"
	tagVulns      = "Vulnerabilities"
	tagJobs       = "Jobs"
	tagAuth       = "Auth"
	tagAdmin      = "Admin"
)

// Route paths registered by more than one operation (GET/PATCH/DELETE on the
// same resource). Kept together so the three stay in sync.
const (
	pathRegistryByID  = "/api/v1/registries/{id}"
	pathNamespaceByID = "/api/v1/namespaces/{id}"
	pathSourceByID    = "/api/v1/sources/{id}"
	pathClusterByID   = "/api/v1/clusters/{id}"
)

// URL schemes, and the ENVIRONMENT value that gates production-only behaviour
// (secure cookies, https callback URLs).
const (
	schemeHTTP    = "http"
	schemeHTTPS   = "https"
	envProduction = "production"
)

// visibilityPrivate mirrors service.VisibilityPrivate; namespaces and registries
// carry the same "public" | "private" vocabulary.
const visibilityPrivate = "private"

// NewRouter creates and configures the chi router with huma API registration.
// corsOrigins is a comma-separated list of allowed origins (e.g. "http://localhost:3000,https://app.example.com").
// frontendURL is used as the default when corsOrigins is empty.
// apiBaseURL, when non-empty, is added to the OpenAPI servers block so clients know where to reach the API.
func NewRouter(h *Handler, corsOrigins, frontendURL, apiBaseURL string) chi.Router {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(middleware.RequestID)
	r.Use(SlogLogger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   parseCORSOrigins(corsOrigins, frontendURL),
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(OptionalAuthenticate(h.authService))
	r.Use(middleware.Timeout(30 * time.Second))

	config := huma.DefaultConfig("OCIDex API", "1.0.0")
	config.Info.Description = "Open Container Initiative Dex — SBOM metadata management service"

	// Security schemes: Bearer API key or session cookie.
	if config.Components == nil {
		config.Components = &huma.Components{}
	}
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearerAuth": { //nolint:gosec
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
	registerNamespaceOps(api, h)
	registerSourceOps(api, h)
	registerClusterOps(api, h)
	registerStatsOps(api, h)
	registerDiscoverOps(api, h)
	registerVulnOps(api, h)
	registerJobOps(api, h)
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
	memberMW := RequireMember(api)
	writeMW := RequireWrite(api)
	sbomOwnerMW := RequireSBOMOwner(api, h.sbomService, h.namespaceService)

	huma.Register(api, huma.Operation{
		OperationID:   "ingest-sbom",
		Method:        http.MethodPost,
		Path:          "/api/v1/sboms",
		Summary:       "Ingest an SBOM",
		Description:   "Accepts a CycloneDX JSON SBOM, validates it, and persists it.",
		Tags:          []string{tagSBOMs},
		MaxBodyBytes:  maxSBOMBodyBytes,
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{memberMW, writeMW},
	}, h.IngestSBOM)

	huma.Register(api, huma.Operation{
		OperationID: "list-sboms",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms",
		Summary:     "List SBOMs",
		Description: "Supports filtering by serial_number and digest query parameters.",
		Tags:        []string{tagSBOMs},
	}, h.ListSBOMs)

	huma.Register(api, huma.Operation{
		OperationID: "lookup-sbom",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms/lookup",
		Summary:     "Resolve an SBOM by artifact name and version",
		Description: "Resolves the ADR-042 qualifier ladder (artifact + version -> +arch -> +flavor), or a digest on its own. " +
			"200 on a unique visible match, 404 on none, 409 with candidates on more than one. " +
			"The digest form is unique by construction and never returns 409.",
		Tags:      []string{tagSBOMs},
		Responses: lookupConflictResponses(api),
	}, h.LookupSBOM)

	huma.Register(api, huma.Operation{
		OperationID: "get-sbom",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms/{id}",
		Summary:     "Get an SBOM",
		Tags:        []string{tagSBOMs},
	}, h.GetSBOM)

	huma.Register(api, huma.Operation{
		OperationID: "get-sbom-dependencies",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms/{id}/dependencies",
		Summary:     "Get SBOM dependency graph",
		Tags:        []string{tagSBOMs},
	}, h.GetSBOMDependencies)

	huma.Register(api, huma.Operation{
		OperationID: "list-sbom-components",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms/{id}/components",
		Summary:     "List components in an SBOM",
		Tags:        []string{tagSBOMs},
	}, h.ListSBOMComponents)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-sbom",
		Method:        http.MethodDelete,
		Path:          "/api/v1/sboms/{id}",
		Summary:       "Delete an SBOM",
		Tags:          []string{tagSBOMs},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{sbomOwnerMW, writeMW},
	}, h.DeleteSBOM)

	huma.Register(api, huma.Operation{
		OperationID: "list-sbom-drift-history",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms/{id}/drift",
		Summary:     "List provenance drift history for an SBOM",
		Tags:        []string{tagSBOMs},
	}, h.ListSBOMDriftHistory)
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
		Tags:        []string{tagComponents},
	}, h.SearchComponents)

	huma.Register(api, huma.Operation{
		OperationID: "search-distinct-components",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/distinct",
		Summary:     "Search distinct components",
		Tags:        []string{tagComponents},
	}, h.SearchDistinctComponents)

	huma.Register(api, huma.Operation{
		OperationID: "list-component-purl-types",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/purl-types",
		Summary:     "List component PURL types",
		Tags:        []string{tagComponents},
	}, h.ListComponentPurlTypes)

	huma.Register(api, huma.Operation{
		OperationID: "get-component-versions",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/versions",
		Summary:     "Get component versions",
		Tags:        []string{tagComponents},
	}, h.GetComponentVersions)

	huma.Register(api, huma.Operation{
		OperationID: "get-component",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/{id}",
		Summary:     "Get a component",
		Tags:        []string{tagComponents},
	}, h.GetComponent)

	huma.Register(api, huma.Operation{
		OperationID: "get-component-vulns",
		Method:      http.MethodGet,
		Path:        "/api/v1/components/{id}/vulns",
		Summary:     "List vulnerabilities for a component",
		Tags:        []string{tagComponents},
	}, h.GetComponentVulns)
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
		Tags:        []string{tagLicenses},
	}, h.ListLicenses)

	huma.Register(api, huma.Operation{
		OperationID: "lookup-license",
		Method:      http.MethodGet,
		Path:        "/api/v1/licenses/lookup",
		Summary:     "Resolve a license by SPDX identifier",
		Description: "spdx_id is a natural key (ADR-042 R3), so this resolver has no qualifier ladder: 200 on a match, 404 on none, never 409.",
		Tags:        []string{tagLicenses},
	}, h.LookupLicense)

	huma.Register(api, huma.Operation{
		OperationID: "list-components-by-license",
		Method:      http.MethodGet,
		Path:        "/api/v1/licenses/{id}/components",
		Summary:     "List components by license",
		Tags:        []string{tagLicenses},
	}, h.ListComponentsByLicense)
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

func registerArtifactOps(api huma.API, h *Handler) {
	artifactOwnerMW := RequireArtifactOwner(api, h.sbomService, h.namespaceService)

	huma.Register(api, huma.Operation{
		OperationID: "list-artifacts",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts",
		Summary:     "List artifacts",
		Tags:        []string{tagArtifacts},
	}, h.ListArtifacts)

	// Registered before the {id} route only for readability — chi matches the
	// literal "lookup" segment ahead of the UUID param regardless of order
	// (ADR-042 R7).
	huma.Register(api, huma.Operation{
		OperationID: "lookup-artifact",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/lookup",
		Summary:     "Resolve an artifact by name",
		Description: "Resolves the ADR-042 qualifier ladder (name -> +type -> +group) to a single artifact. " +
			"200 on a unique visible match, 404 on none, 409 with candidates on more than one.",
		Tags:      []string{tagArtifacts},
		Responses: lookupConflictResponses(api),
	}, h.LookupArtifact)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}",
		Summary:     "Get an artifact",
		Tags:        []string{tagArtifacts},
	}, h.GetArtifact)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-artifact",
		Method:        http.MethodDelete,
		Path:          "/api/v1/artifacts/{id}",
		Summary:       "Delete an artifact",
		Tags:          []string{tagArtifacts},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{artifactOwnerMW, RequireWrite(api)},
	}, h.DeleteArtifact)

	huma.Register(api, huma.Operation{
		OperationID: "list-artifact-sboms",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/sboms",
		Summary:     "List SBOMs for an artifact",
		Tags:        []string{tagArtifacts},
	}, h.ListArtifactSBOMs)

	huma.Register(api, huma.Operation{
		OperationID: "list-artifact-versions",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/versions",
		Summary:     "List versions for an artifact",
		Tags:        []string{tagArtifacts},
	}, h.ListArtifactVersions)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact-changelog",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/changelog",
		Summary:     "Get artifact changelog",
		Tags:        []string{tagArtifacts},
	}, h.GetArtifactChangelog)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact-license-summary",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/license-summary",
		Summary:     "Get artifact license summary",
		Tags:        []string{tagArtifacts},
	}, h.GetArtifactLicenseSummary)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact-vuln-summary",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/vuln-summary",
		Summary:     "Get artifact vulnerability summary",
		Tags:        []string{tagArtifacts},
	}, h.GetArtifactVulnSummary)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact-usages",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/usages",
		Summary:     "List artifacts that ship this artifact",
		Description: "Artifacts whose latest SBOM contains a component matching this artifact (ADR-041).",
		Tags:        []string{tagArtifacts},
	}, h.GetArtifactUsages)

	huma.Register(api, huma.Operation{
		OperationID: "get-artifact-contains",
		Method:      http.MethodGet,
		Path:        "/api/v1/artifacts/{id}/contains",
		Summary:     "List tracked artifacts this artifact ships",
		Description: "Tracked artifacts matched by components of this artifact's latest SBOM (ADR-041).",
		Tags:        []string{tagArtifacts},
	}, h.GetArtifactContains)
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

func registerDiffOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "diff-sboms",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms/diff",
		Summary:     "Diff two SBOMs",
		Description: "Computes the component diff between two SBOMs.",
		Tags:        []string{tagSBOMs},
	}, h.DiffSBOMs)

	huma.Register(api, huma.Operation{
		OperationID: "diff-tree",
		Method:      http.MethodGet,
		Path:        "/api/v1/sboms/diff-tree",
		Summary:     "Diff two SBOMs with dependency tree",
		Description: "Returns the package-only diff between two SBOMs together with the filtered (non-file) dependency graph of the target SBOM for tree-structured rendering.",
		Tags:        []string{tagSBOMs},
	}, h.GetDiffTree)
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

func registerWebhookOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID:   "registry-webhook",
		Method:        http.MethodPost,
		Path:          "/api/v1/registries/{id}/webhook",
		Summary:       "Receive registry push notifications",
		Tags:          []string{tagRegistries},
		MaxBodyBytes:  64 * 1024,
		DefaultStatus: http.StatusAccepted,
		Security:      []map[string][]string{},
	}, h.HandleRegistryWebhook)
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

func registerRegistryOps(api huma.API, h *Handler) {
	ownerMW := RequireRegistryOwner(api, h.registryService)
	adminMW := RequireAdmin(api)
	authMW := RequireAuthenticated(api)
	writeMW := RequireWrite(api)

	huma.Register(api, huma.Operation{
		OperationID:   "test-registry-connection",
		Method:        http.MethodPost,
		Path:          "/api/v1/registries/test-connection",
		Summary:       "Test registry connectivity",
		Description:   "Probes the registry's /v2/ endpoint and reports whether it is reachable. Admin-only.",
		Tags:          []string{tagRegistries},
		DefaultStatus: http.StatusOK,
		Middlewares:   huma.Middlewares{adminMW, writeMW},
	}, h.TestRegistryConnection)

	huma.Register(api, huma.Operation{
		OperationID: "list-registries",
		Method:      http.MethodGet,
		Path:        "/api/v1/registries",
		Summary:     "List registries",
		Tags:        []string{tagRegistries},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListRegistries)

	huma.Register(api, huma.Operation{
		OperationID: "get-registry-trust-summary",
		Method:      http.MethodGet,
		Path:        "/api/v1/registries/trust-summary",
		Summary:     "Per-registry signing-status counts",
		Description: "Counts artifacts by current signing status, per registry, across the registries the caller can see. Admins get every registry; a namespace owner gets their own.",
		Tags:        []string{tagRegistries},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetRegistryTrustSummary)

	huma.Register(api, huma.Operation{
		OperationID: "list-recent-drift",
		Method:      http.MethodGet,
		Path:        "/api/v1/registries/drift-feed",
		Summary:     "Recent provenance drift feed",
		Description: "Most recent provenance drift events across the registries the caller can see. Admins get every registry; a namespace owner gets their own.",
		Tags:        []string{tagRegistries},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListRecentDrift)

	huma.Register(api, huma.Operation{
		OperationID:   "create-registry",
		Method:        http.MethodPost,
		Path:          "/api/v1/registries",
		Summary:       "Create a registry",
		Tags:          []string{tagRegistries},
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{authMW, writeMW},
	}, h.CreateRegistry)

	huma.Register(api, huma.Operation{
		OperationID: "get-registry",
		Method:      http.MethodGet,
		Path:        pathRegistryByID,
		Summary:     "Get a registry",
		Tags:        []string{tagRegistries},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetRegistry)

	huma.Register(api, huma.Operation{
		OperationID: "get-registry-by-name",
		Method:      http.MethodGet,
		Path:        "/api/v1/registries/by-name/{name}",
		Summary:     "Get a registry by name",
		Tags:        []string{tagRegistries},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetRegistryByName)

	huma.Register(api, huma.Operation{
		OperationID: "update-registry",
		Method:      http.MethodPatch,
		Path:        pathRegistryByID,
		Summary:     "Update a registry (partial)",
		Tags:        []string{tagRegistries},
		Middlewares: huma.Middlewares{ownerMW, writeMW},
	}, h.UpdateRegistry)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-registry",
		Method:        http.MethodDelete,
		Path:          pathRegistryByID,
		Summary:       "Delete a registry",
		Tags:          []string{tagRegistries},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{ownerMW, writeMW},
	}, h.DeleteRegistry)

	huma.Register(api, huma.Operation{
		OperationID:   "scan-registry",
		Method:        http.MethodPost,
		Path:          "/api/v1/registries/{id}/scan",
		Summary:       "Trigger ad-hoc registry scan",
		Description:   "Walks the registry catalog, filters by configured patterns, and queues scan requests for all matching images.",
		Tags:          []string{tagRegistries},
		DefaultStatus: http.StatusAccepted,
		Middlewares:   huma.Middlewares{ownerMW, writeMW},
	}, h.ScanRegistry)

	huma.Register(api, huma.Operation{
		OperationID: "regenerate-webhook-secret",
		Method:      http.MethodPost,
		Path:        "/api/v1/registries/{id}/webhook-secret",
		Summary:     "Regenerate webhook secret",
		Description: "Generates a new webhook secret for the registry. The previous secret is immediately invalidated.",
		Tags:        []string{tagRegistries},
		Middlewares: huma.Middlewares{ownerMW, writeMW},
	}, h.RegenerateWebhookSecret)
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

func registerNamespaceOps(api huma.API, h *Handler) {
	authMW := RequireAuthenticated(api)
	writeMW := RequireWrite(api)

	huma.Register(api, huma.Operation{
		OperationID: "list-namespaces",
		Method:      http.MethodGet,
		Path:        "/api/v1/namespaces",
		Summary:     "List namespaces",
		Description: "Namespaces owned by the caller plus every public namespace.",
		Tags:        []string{tagNamespaces},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListNamespaces)

	huma.Register(api, huma.Operation{
		OperationID:   "create-namespace",
		Method:        http.MethodPost,
		Path:          "/api/v1/namespaces",
		Summary:       "Create a namespace",
		Tags:          []string{tagNamespaces},
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{authMW, writeMW},
	}, h.CreateNamespace)

	huma.Register(api, huma.Operation{
		OperationID: "get-namespace-by-name",
		Method:      http.MethodGet,
		Path:        "/api/v1/namespaces/by-name/{name}",
		Summary:     "Get a namespace by name",
		Tags:        []string{tagNamespaces},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetNamespaceByName)

	huma.Register(api, huma.Operation{
		OperationID: "get-namespace",
		Method:      http.MethodGet,
		Path:        pathNamespaceByID,
		Summary:     "Get a namespace",
		Tags:        []string{tagNamespaces},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetNamespace)

	huma.Register(api, huma.Operation{
		OperationID: "update-namespace",
		Method:      http.MethodPatch,
		Path:        pathNamespaceByID,
		Summary:     "Update a namespace (partial)",
		Tags:        []string{tagNamespaces},
		Middlewares: huma.Middlewares{authMW, writeMW},
	}, h.UpdateNamespace)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-namespace",
		Method:        http.MethodDelete,
		Path:          pathNamespaceByID,
		Summary:       "Delete a namespace",
		Description:   "Removes the namespace and everything ingested under it. Owner or admin only.",
		Tags:          []string{tagNamespaces},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{authMW, writeMW},
	}, h.DeleteNamespace)
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

func registerSourceOps(api huma.API, h *Handler) {
	authMW := RequireAuthenticated(api)
	writeMW := RequireWrite(api)

	huma.Register(api, huma.Operation{
		OperationID: "list-sources",
		Method:      http.MethodGet,
		Path:        "/api/v1/sources",
		Summary:     "List sources",
		Description: "Ingest channels visible to the caller, optionally scoped to one namespace.",
		Tags:        []string{tagSources},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListSources)

	huma.Register(api, huma.Operation{
		OperationID:   "create-source",
		Method:        http.MethodPost,
		Path:          "/api/v1/sources",
		Summary:       "Create an upload source",
		Description:   "Creates a source with kind 'upload'. OCI registry sources are created via POST /api/v1/registries.",
		Tags:          []string{tagSources},
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{authMW, writeMW},
	}, h.CreateSource)

	huma.Register(api, huma.Operation{
		OperationID: "get-source",
		Method:      http.MethodGet,
		Path:        pathSourceByID,
		Summary:     "Get a source",
		Tags:        []string{tagSources},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetSource)

	huma.Register(api, huma.Operation{
		OperationID: "update-source",
		Method:      http.MethodPatch,
		Path:        pathSourceByID,
		Summary:     "Rename a source",
		Tags:        []string{tagSources},
		Middlewares: huma.Middlewares{authMW, writeMW},
	}, h.UpdateSource)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-source",
		Method:        http.MethodDelete,
		Path:          pathSourceByID,
		Summary:       "Delete a source",
		Tags:          []string{tagSources},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{authMW, writeMW},
	}, h.DeleteSource)
}

// ---------------------------------------------------------------------------
// Clusters
// ---------------------------------------------------------------------------

func registerClusterOps(api huma.API, h *Handler) {
	authMW := RequireAuthenticated(api)
	writeMW := RequireWrite(api)

	huma.Register(api, huma.Operation{
		OperationID: "list-clusters",
		Method:      http.MethodGet,
		Path:        "/api/v1/clusters",
		Summary:     "List clusters",
		Description: "Kubernetes clusters visible to the caller, optionally scoped to one namespace.",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListClusters)

	huma.Register(api, huma.Operation{
		OperationID: "list-my-clusters",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me/clusters",
		Summary:     "List my clusters",
		Description: "Clusters in namespaces the caller owns.",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListMyClusters)

	huma.Register(api, huma.Operation{
		OperationID:   "create-cluster",
		Method:        http.MethodPost,
		Path:          "/api/v1/clusters",
		Summary:       "Register a cluster",
		Description:   "Registers a Kubernetes cluster that an agent will report running workloads for.",
		Tags:          []string{tagClusters},
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{authMW, writeMW},
	}, h.CreateCluster)

	huma.Register(api, huma.Operation{
		OperationID: "get-cluster",
		Method:      http.MethodGet,
		Path:        pathClusterByID,
		Summary:     "Get a cluster",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetCluster)

	huma.Register(api, huma.Operation{
		OperationID: "update-cluster",
		Method:      http.MethodPatch,
		Path:        pathClusterByID,
		Summary:     "Rename a cluster",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW, writeMW},
	}, h.UpdateCluster)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-cluster",
		Method:        http.MethodDelete,
		Path:          pathClusterByID,
		Summary:       "Delete a cluster",
		Description:   "Removes the cluster and the inventory it has reported. Ingested SBOMs are untouched.",
		Tags:          []string{tagClusters},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{authMW, writeMW},
	}, h.DeleteCluster)

	// Inventory push is a mutation despite reading like a report: it replaces
	// the cluster's entire workload set (ADR-044 K7).
	huma.Register(api, huma.Operation{
		OperationID: "put-cluster-inventory",
		Method:      http.MethodPost,
		Path:        "/api/v1/clusters/{id}/inventory",
		Summary:     "Push a cluster inventory snapshot",
		Description: "Replaces the cluster's workload set with the complete snapshot in the body. Workloads absent from the body are deleted.",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW, writeMW},
	}, h.PutInventory)

	huma.Register(api, huma.Operation{
		OperationID: "list-cluster-workloads",
		Method:      http.MethodGet,
		Path:        "/api/v1/clusters/{id}/workloads",
		Summary:     "List running workloads",
		Description: "What the cluster last reported running, each row joined to the SBOM its image digest matches, with coverage counts for the workloads that matched nothing.",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListClusterWorkloads)

	huma.Register(api, huma.Operation{
		OperationID: "list-cluster-images",
		Method:      http.MethodGet,
		Path:        "/api/v1/clusters/{id}/images",
		Summary:     "List running images",
		Description: "The same inventory as the workload listing, grouped by image: one row per distinct image with the workloads running it collapsed into counts. Carries the same coverage counts.",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListClusterImages)

	huma.Register(api, huma.Operation{
		OperationID: "list-cluster-k8s-namespaces",
		Method:      http.MethodGet,
		Path:        "/api/v1/clusters/{id}/k8s-namespaces",
		Summary:     "List reported Kubernetes namespaces",
		Description: "The namespace facet for the workload filter, covering the whole cluster rather than the current page of workloads.",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListClusterNamespaces)

	huma.Register(api, huma.Operation{
		OperationID: "list-cluster-unknown-images",
		Method:      http.MethodGet,
		Path:        "/api/v1/clusters/{id}/unknown-images",
		Summary:     "List running images with no ingested SBOM",
		Description: "The No-SBOM coverage gap grouped by image, each resolved against the registries of the cluster's own namespace so the row says whether ingesting it is possible and, if not, why.",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListClusterUnknownImages)

	huma.Register(api, huma.Operation{
		OperationID: "ingest-cluster-unknown-images",
		Method:      http.MethodPost,
		Path:        "/api/v1/clusters/{id}/ingest-unknown",
		Summary:     "Scan the cluster's unscanned running images",
		Description: "Submits a scan job for every running image with no SBOM whose host resolves to an enabled registry in the cluster's own namespace, and reports per-reason counts for the ones it could not. Repeat runs enqueue nothing new: scan jobs are keyed on (registry, digest).",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW, writeMW},
	}, h.IngestUnknown)

	huma.Register(api, huma.Operation{
		OperationID: "list-cluster-vulns",
		Method:      http.MethodGet,
		Path:        "/api/v1/clusters/{id}/vulns",
		Summary:     "List vulnerabilities running in a cluster",
		Description: "Vulnerabilities carried by images this cluster is actually running, most severe first. " +
			"The response also carries workload coverage: these findings describe only the workloads OCIDex " +
			"could match to an SBOM, and are silent about the rest (ADR-044).",
		Tags:        []string{tagClusters},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListClusterVulns)
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

func registerStatsOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-dashboard-stats",
		Method:      http.MethodGet,
		Path:        "/api/v1/stats",
		Summary:     "Get dashboard summary statistics",
		Tags:        []string{"Stats"},
	}, h.GetDashboardStats)
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// registerDiscoverOps registers the public landing-page aggregate. No auth
// middleware: the payload is identical for every caller, so a session would only
// add a cost and a cache key without changing a byte of the response.
func registerDiscoverOps(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "get-discovery",
		Method:      http.MethodGet,
		Path:        "/api/v1/discover",
		Summary:     "Get the public discovery payload",
		Description: "Popular artifacts, recent activity, widest-blast-radius vulnerabilities " +
			"and license spread across public namespaces only. Computed out of band; while " +
			"the first snapshot is still being built the response reports warming with empty " +
			"sections.",
		Tags: []string{"Discovery"},
	}, h.GetDiscovery)
}

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

func registerVulnOps(api huma.API, h *Handler) {
	authMW := RequireAuthenticated(api)

	huma.Register(api, huma.Operation{
		OperationID: "list-top-vulnerabilities",
		Method:      http.MethodGet,
		Path:        "/api/v1/vulns",
		Summary:     "List top vulnerabilities",
		Tags:        []string{tagVulns},
	}, h.ListTopVulnerabilities)
	huma.Register(api, huma.Operation{
		OperationID: "get-vulnerability",
		Method:      http.MethodGet,
		Path:        "/api/v1/vulns/{id}",
		Summary:     "Get vulnerability detail",
		Tags:        []string{tagVulns},
	}, h.GetVulnerability)

	huma.Register(api, huma.Operation{
		OperationID: "list-vulnerability-workloads",
		Method:      http.MethodGet,
		Path:        "/api/v1/vulns/{id}/workloads",
		Summary:     "List running workloads affected by a vulnerability",
		Description: "Kubernetes workloads currently running an image that carries this vulnerability, " +
			"across every cluster visible to the caller or narrowed to one with cluster_id.",
		Tags:        []string{tagVulns},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListVulnWorkloads)
}

// ---------------------------------------------------------------------------
// Scan Jobs
// ---------------------------------------------------------------------------

func registerJobOps(api huma.API, h *Handler) {
	authMW := RequireAuthenticated(api)
	adminMW := RequireAdmin(api)
	writeMW := RequireWrite(api)

	huma.Register(api, huma.Operation{
		OperationID: "list-scan-jobs",
		Method:      http.MethodGet,
		Path:        "/api/v1/jobs",
		Summary:     "List scan jobs",
		Description: "Returns a paginated list of scan pipeline jobs, optionally filtered by state.",
		Tags:        []string{tagJobs},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListScanJobs)

	huma.Register(api, huma.Operation{
		OperationID: "get-scan-job",
		Method:      http.MethodGet,
		Path:        "/api/v1/jobs/{id}",
		Summary:     "Get a scan job",
		Tags:        []string{tagJobs},
		Middlewares: huma.Middlewares{authMW},
	}, h.GetScanJob)

	huma.Register(api, huma.Operation{
		OperationID: "retry-scan-job",
		Method:      http.MethodPost,
		Path:        "/api/v1/admin/jobs/{id}/retry",
		Summary:     "Retry a failed scan job",
		Description: "Resets a 'failed' scan_jobs row back to 'queued' so it gets reprocessed. Admin-only.",
		Tags:        []string{tagJobs, tagAdmin},
		Middlewares: huma.Middlewares{adminMW, writeMW},
	}, h.RetryScanJob)

	huma.Register(api, huma.Operation{
		OperationID: "retry-all-failed-scan-jobs",
		Method:      http.MethodPost,
		Path:        "/api/v1/admin/jobs/retry-failed",
		Summary:     "Retry every failed scan job",
		Description: "Resets every scan_jobs row whose state is 'failed' back to 'queued' and returns the row count. Admin-only.",
		Tags:        []string{tagJobs, tagAdmin},
		Middlewares: huma.Middlewares{adminMW, writeMW},
	}, h.RetryAllFailedScanJobs)

	huma.Register(api, huma.Operation{
		OperationID: "list-enrichment-jobs",
		Method:      http.MethodGet,
		Path:        "/api/v1/enrichment-jobs",
		Summary:     "List enrichment jobs",
		Description: "Returns a paginated list of enrichment pipeline jobs, optionally filtered by state and/or enricher.",
		Tags:        []string{tagJobs},
		Middlewares: huma.Middlewares{authMW},
	}, h.ListEnrichmentJobs)

	huma.Register(api, huma.Operation{
		OperationID: "enrichment-jobs-summary",
		Method:      http.MethodGet,
		Path:        "/api/v1/enrichment-jobs/summary",
		Summary:     "Per-enricher enrichment job counts",
		Description: "Returns one row per (enricher, state) with its count, for the per-enricher health matrix.",
		Tags:        []string{tagJobs},
		Middlewares: huma.Middlewares{authMW},
	}, h.EnrichmentJobsSummary)

	huma.Register(api, huma.Operation{
		OperationID: "retry-enrichment-job",
		Method:      http.MethodPost,
		Path:        "/api/v1/admin/enrichment-jobs/{id}/retry",
		Summary:     "Retry a failed enrichment job",
		Description: "Resets a 'failed' enrichment_jobs row back to 'queued' so it gets reprocessed. Admin-only.",
		Tags:        []string{tagJobs, tagAdmin},
		Middlewares: huma.Middlewares{adminMW, writeMW},
	}, h.RetryEnrichmentJob)

	huma.Register(api, huma.Operation{
		OperationID: "retry-all-failed-enrichment-jobs",
		Method:      http.MethodPost,
		Path:        "/api/v1/admin/enrichment-jobs/retry-failed",
		Summary:     "Retry every failed enrichment job",
		Description: "Resets every 'failed' enrichment_jobs row back to 'queued', optionally scoped to one enricher, and returns the row count. Admin-only.",
		Tags:        []string{tagJobs, tagAdmin},
		Middlewares: huma.Middlewares{adminMW, writeMW},
	}, h.RetryAllFailedEnrichmentJobs)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseCORSOrigins splits a comma-separated origins string into a slice.
// When raw is empty, frontendURL is used as the default allowed origin.
func parseCORSOrigins(raw, frontendURL string) []string {
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			origins = append(origins, s)
		}
	}
	if len(origins) == 0 && frontendURL != "" {
		return []string{frontendURL}
	}
	for _, o := range origins {
		if o == "*" {
			slog.Warn("CORS: wildcard origin '*' used with AllowCredentials — this is insecure in production")
			break
		}
	}
	return origins
}
