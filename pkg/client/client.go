package client

import "context"

// Client is the interface for the OCIDex HTTP API.
// The concrete implementation is httpClient, constructed via New.
// Consumers may substitute a FakeClient for testing.
type Client interface {
	// Registry + auth

	ListRegistries(ctx context.Context, opts PageOpts) (Page[RegistryResponse], error)
	GetRegistry(ctx context.Context, id string) (RegistryResponse, error)
	CreateRegistry(ctx context.Context, body CreateRegistryInputBody) (CreateRegistryResponseBody, error)
	UpdateRegistry(ctx context.Context, id string, body UpdateRegistryInputBody) (RegistryResponse, error)
	DeleteRegistry(ctx context.Context, id string) error
	ScanRegistry(ctx context.Context, id string) (ScanRegistryOutputBody, error)
	TestRegistryConnection(ctx context.Context, id string, body TestRegistryConnectionInputBody) (TestRegistryConnectionOutputBody, error)
	RegenerateWebhookSecret(ctx context.Context, id string) (RegenerateWebhookSecretOutputBody, error)

	CreateAPIKey(ctx context.Context, body CreateAPIKeyInputBody) (CreateAPIKeyOutputBody, error)
	ListAPIKeys(ctx context.Context) ([]KeyMetaResponse, error)
	DeleteAPIKey(ctx context.Context, id string) error
	GetCurrentUser(ctx context.Context) (MeOutputBody, error)

	// SBOM + artifact

	IngestSBOM(ctx context.Context, data []byte, params IngestSbomParams) (IngestSBOMOutputBody, error)
	GetSBOM(ctx context.Context, id string, includeRaw bool) (SBOMDetail, error)
	ListSBOMs(ctx context.Context, opts PageOpts) (Page[SBOMSummary], error)
	DeleteSBOM(ctx context.Context, id string) error
	DiffSBOMs(ctx context.Context, fromID, toID string) (Changelog, error)
	GetDiffTree(ctx context.Context, fromID, toID string) (DiffTree, error)

	ListArtifacts(ctx context.Context, opts PageOpts) (Page[ArtifactSummary], error)
	GetArtifact(ctx context.Context, id string) (ArtifactDetail, error)
	GetArtifactChangelog(ctx context.Context, id string, params GetArtifactChangelogParams) (Changelog, error)
	GetArtifactLicenseSummary(ctx context.Context, id string) (GetArtifactLicenseSummaryOutputBody, error)
	ListArtifactSBOMs(ctx context.Context, id string, opts PageOpts) (Page[SBOMSummary], error)
	ListArtifactVersions(ctx context.Context, id string, opts PageOpts) (Page[ArtifactVersionSummary], error)

	// Component + job + stats

	SearchComponents(ctx context.Context, query string, opts PageOpts) (Page[ComponentSummary], error)
	SearchDistinctComponents(ctx context.Context, query string, opts PageOpts) (Page[DistinctComponentSummary], error)
	GetComponent(ctx context.Context, id string) (ComponentDetail, error)
	GetComponentVersions(ctx context.Context, id string) (GetComponentVersionsOutputBody, error)
	ListComponentPurlTypes(ctx context.Context) ([]string, error)
	ListSBOMComponents(ctx context.Context, sbomID string, opts PageOpts) (Page[ComponentSummary], error)
	GetSBOMDependencies(ctx context.Context, sbomID string) (DependencyGraph, error)

	ListJobs(ctx context.Context, opts PageOpts) (Page[ScanJobResponse], error)
	GetJob(ctx context.Context, id string) (ScanJobResponse, error)

	GetDashboardStats(ctx context.Context) (DashboardStatsOutputBody, error)
}
