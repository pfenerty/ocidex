package client

import "context"

// Client is the interface for the OCIDex HTTP API.
// The concrete implementation is httpClient, constructed via New.
// Consumers may substitute a FakeClient for testing.
type Client interface {
	// Registry + auth

	ListRegistries(ctx context.Context, opts PageOpts) (Page[RegistryResponse], error)
	GetRegistry(ctx context.Context, id string) (RegistryResponse, error)
	GetRegistryByName(ctx context.Context, name string) (RegistryResponse, error)
	CreateRegistry(ctx context.Context, body CreateRegistryInputBody) (CreateRegistryResponseBody, error)
	UpdateRegistry(ctx context.Context, id string, body UpdateRegistryInputBody) (RegistryResponse, error)
	DeleteRegistry(ctx context.Context, id string) error
	ScanRegistry(ctx context.Context, id string) (ScanRegistryOutputBody, error)
	TestRegistryConnection(ctx context.Context, body TestRegistryConnectionInputBody) (TestRegistryConnectionOutputBody, error)
	RegenerateWebhookSecret(ctx context.Context, id string) (RegenerateWebhookSecretOutputBody, error)

	// Namespace + source

	ListNamespaces(ctx context.Context) ([]NamespaceResponse, error)
	GetNamespace(ctx context.Context, id string) (NamespaceResponse, error)
	GetNamespaceByName(ctx context.Context, name string) (NamespaceResponse, error)
	CreateNamespace(ctx context.Context, body CreateNamespaceInputBody) (NamespaceResponse, error)
	UpdateNamespace(ctx context.Context, id string, body UpdateNamespaceInputBody) (NamespaceResponse, error)
	DeleteNamespace(ctx context.Context, id string) error

	ListSources(ctx context.Context, namespaceID string) ([]SourceResponse, error)
	GetSource(ctx context.Context, id string) (SourceResponse, error)
	CreateSource(ctx context.Context, body CreateSourceInputBody) (SourceResponse, error)
	UpdateSource(ctx context.Context, id string, body UpdateSourceInputBody) (SourceResponse, error)
	DeleteSource(ctx context.Context, id string) error

	CreateAPIKey(ctx context.Context, body CreateAPIKeyInputBody) (CreateAPIKeyOutputBody, error)
	ListAPIKeys(ctx context.Context) ([]KeyMetaResponse, error)
	DeleteAPIKey(ctx context.Context, id string) error
	GetCurrentUser(ctx context.Context) (MeOutputBody, error)

	// SBOM + artifact

	IngestSBOM(ctx context.Context, data []byte, params IngestSbomParams) (IngestSBOMOutputBody, error)
	GetSBOM(ctx context.Context, id string, includeRaw bool) (SBOMDetail, error)
	ListSBOMs(ctx context.Context, filter SBOMFilter, opts PageOpts) (CursorPage[SBOMSummary], error)
	DeleteSBOM(ctx context.Context, id string) error
	DiffSBOMs(ctx context.Context, fromID, toID string) (ChangelogEntry, error)
	GetDiffTree(ctx context.Context, fromID, toID string) (DiffTree, error)

	ListArtifacts(ctx context.Context, filter ArtifactFilter, opts PageOpts) (CursorPage[ArtifactSummary], error)
	GetArtifact(ctx context.Context, id string) (ArtifactDetail, error)
	GetArtifactChangelog(ctx context.Context, id string, params GetArtifactChangelogParams) (Changelog, error)
	GetArtifactLicenseSummary(ctx context.Context, id string) (GetArtifactLicenseSummaryOutputBody, error)
	ListArtifactSBOMs(ctx context.Context, id string, opts PageOpts) (CursorPage[SBOMSummary], error)
	ListArtifactVersions(ctx context.Context, id string, opts PageOpts) (Page[ArtifactVersionSummary], error)

	// Name-keyed resolvers (ADR-042). Each returns the same body as its UUID
	// counterpart, ErrNotFound when nothing visible matches, and — for the two
	// that can be ambiguous — a *ConflictError listing the candidates.

	LookupArtifact(ctx context.Context, params LookupArtifactParams) (ArtifactDetail, error)
	LookupSBOM(ctx context.Context, params LookupSbomParams) (SBOMDetail, error)
	LookupLicense(ctx context.Context, spdxID string) (LicenseCount, error)

	// Component + job + stats

	SearchComponents(ctx context.Context, filter ComponentFilter, opts PageOpts) (Page[ComponentSummary], error)
	SearchDistinctComponents(ctx context.Context, filter DistinctComponentFilter, opts PageOpts) (Page[DistinctComponentSummary], error)
	GetComponent(ctx context.Context, id string) (ComponentDetail, error)
	GetComponentVersions(ctx context.Context, params GetComponentVersionsParams) (GetComponentVersionsOutputBody, error)
	ListComponentPurlTypes(ctx context.Context) ([]string, error)
	ListSBOMComponents(ctx context.Context, sbomID string) ([]ComponentSummary, error)
	GetSBOMDependencies(ctx context.Context, sbomID string) (DependencyGraph, error)

	ListJobs(ctx context.Context, filter JobFilter, opts PageOpts) (Page[ScanJobResponse], error)
	GetJob(ctx context.Context, id string) (ScanJobResponse, error)
	RetryJob(ctx context.Context, id string) error

	GetDashboardStats(ctx context.Context) (DashboardStatsOutputBody, error)
}
