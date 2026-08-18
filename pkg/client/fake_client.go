package client

import (
	"context"
	"encoding/json"
)

// FakeClient is a test double that implements Client.
// Set function fields to stub individual methods; unset fields return zero values and nil error.
type FakeClient struct {
	// Registry + auth
	ListRegistriesFn          func(ctx context.Context, opts PageOpts) (Page[RegistryResponse], error)
	GetRegistryFn             func(ctx context.Context, id string) (RegistryResponse, error)
	GetRegistryByNameFn       func(ctx context.Context, name string) (RegistryResponse, error)
	CreateRegistryFn          func(ctx context.Context, body CreateRegistryInputBody) (CreateRegistryResponseBody, error)
	UpdateRegistryFn          func(ctx context.Context, id string, body UpdateRegistryInputBody) (RegistryResponse, error)
	DeleteRegistryFn          func(ctx context.Context, id string) error
	ScanRegistryFn            func(ctx context.Context, id string) (ScanRegistryOutputBody, error)
	TestRegistryConnectionFn  func(ctx context.Context, body TestRegistryConnectionInputBody) (TestRegistryConnectionOutputBody, error)
	RegenerateWebhookSecretFn func(ctx context.Context, id string) (RegenerateWebhookSecretOutputBody, error)

	// Namespace + source
	ListNamespacesFn     func(ctx context.Context) ([]NamespaceResponse, error)
	GetNamespaceFn       func(ctx context.Context, id string) (NamespaceResponse, error)
	GetNamespaceByNameFn func(ctx context.Context, name string) (NamespaceResponse, error)
	CreateNamespaceFn    func(ctx context.Context, body CreateNamespaceInputBody) (NamespaceResponse, error)
	UpdateNamespaceFn    func(ctx context.Context, id string, body UpdateNamespaceInputBody) (NamespaceResponse, error)
	DeleteNamespaceFn    func(ctx context.Context, id string) error

	ListSourcesFn  func(ctx context.Context, namespaceID string) ([]SourceResponse, error)
	GetSourceFn    func(ctx context.Context, id string) (SourceResponse, error)
	CreateSourceFn func(ctx context.Context, body CreateSourceInputBody) (SourceResponse, error)
	UpdateSourceFn func(ctx context.Context, id string, body UpdateSourceInputBody) (SourceResponse, error)
	DeleteSourceFn func(ctx context.Context, id string) error

	CreateAPIKeyFn   func(ctx context.Context, body CreateAPIKeyInputBody) (CreateAPIKeyOutputBody, error)
	ListAPIKeysFn    func(ctx context.Context) ([]KeyMetaResponse, error)
	DeleteAPIKeyFn   func(ctx context.Context, id string) error
	GetCurrentUserFn func(ctx context.Context) (MeOutputBody, error)

	// Cluster inventory
	ListClustersFn         func(ctx context.Context, namespaceID string) ([]ClusterResponse, error)
	GetClusterFn           func(ctx context.Context, id string) (ClusterResponse, error)
	CreateClusterFn        func(ctx context.Context, body CreateClusterInputBody) (ClusterResponse, error)
	UpdateClusterFn        func(ctx context.Context, id string, body UpdateClusterInputBody) (ClusterResponse, error)
	DeleteClusterFn        func(ctx context.Context, id string) error
	PutInventoryFn         func(ctx context.Context, clusterID string, workloads []InventoryWorkload) (PutInventoryOutputBody, error)
	ListClusterWorkloadsFn func(ctx context.Context, clusterID string) ([]ClusterWorkloadResponse, WorkloadCoverageResponse, error)

	// SBOM + artifact
	IngestSBOMFn                func(ctx context.Context, data []byte, params IngestSbomParams) (IngestSBOMOutputBody, error)
	GetSBOMFn                   func(ctx context.Context, id string, includeRaw bool) (SBOMDetail, error)
	ListSBOMsFn                 func(ctx context.Context, filter SBOMFilter, opts PageOpts) (CursorPage[SBOMSummary], error)
	DeleteSBOMFn                func(ctx context.Context, id string) error
	DiffSBOMsFn                 func(ctx context.Context, fromID, toID string) (ChangelogEntry, error)
	GetDiffTreeFn               func(ctx context.Context, fromID, toID string) (DiffTree, error)
	ListArtifactsFn             func(ctx context.Context, filter ArtifactFilter, opts PageOpts) (CursorPage[ArtifactSummary], error)
	GetArtifactFn               func(ctx context.Context, id string) (ArtifactDetail, error)
	GetArtifactChangelogFn      func(ctx context.Context, id string, params GetArtifactChangelogParams) (Changelog, error)
	GetArtifactLicenseSummaryFn func(ctx context.Context, id string) (GetArtifactLicenseSummaryOutputBody, error)
	ListArtifactSBOMsFn         func(ctx context.Context, id string, opts PageOpts) (CursorPage[SBOMSummary], error)
	ListArtifactVersionsFn      func(ctx context.Context, id string, opts PageOpts) (Page[ArtifactVersionSummary], error)

	// Name-keyed resolvers (ADR-042)
	LookupArtifactFn func(ctx context.Context, params LookupArtifactParams) (ArtifactDetail, error)
	LookupSBOMFn     func(ctx context.Context, params LookupSbomParams) (SBOMDetail, error)
	LookupLicenseFn  func(ctx context.Context, spdxID string) (LicenseCount, error)

	// Vulnerabilities
	GetArtifactVulnSummaryFn func(ctx context.Context, artifactID string) (VulnSummary, error)
	GetComponentVulnsFn      func(ctx context.Context, componentID string) ([]ComponentVulnEntry, error)
	GetVulnerabilityFn       func(ctx context.Context, vulnID string, opts PageOpts) (GetVulnerabilityOutputBody, error)

	// Component + job + stats
	SearchComponentsFn         func(ctx context.Context, filter ComponentFilter, opts PageOpts) (Page[ComponentSummary], error)
	SearchDistinctComponentsFn func(ctx context.Context, filter DistinctComponentFilter, opts PageOpts) (Page[DistinctComponentSummary], error)
	GetComponentFn             func(ctx context.Context, id string) (ComponentDetail, error)
	GetComponentVersionsFn     func(ctx context.Context, params GetComponentVersionsParams) (GetComponentVersionsOutputBody, error)
	ListComponentPurlTypesFn   func(ctx context.Context) ([]string, error)
	ListSBOMComponentsFn       func(ctx context.Context, sbomID string) ([]ComponentSummary, error)
	GetSBOMDependenciesFn      func(ctx context.Context, sbomID string) (DependencyGraph, error)

	ListJobsFn          func(ctx context.Context, filter JobFilter, opts PageOpts) (Page[ScanJobResponse], error)
	GetJobFn            func(ctx context.Context, id string) (ScanJobResponse, error)
	RetryJobFn          func(ctx context.Context, id string) error
	GetDashboardStatsFn func(ctx context.Context) (DashboardStatsOutputBody, error)

	GetOpenAPISpecFn func(ctx context.Context) (json.RawMessage, error)
}

func (f *FakeClient) ListRegistries(ctx context.Context, opts PageOpts) (Page[RegistryResponse], error) {
	if f.ListRegistriesFn != nil {
		return f.ListRegistriesFn(ctx, opts)
	}
	return Page[RegistryResponse]{}, nil
}

func (f *FakeClient) GetRegistry(ctx context.Context, id string) (RegistryResponse, error) {
	if f.GetRegistryFn != nil {
		return f.GetRegistryFn(ctx, id)
	}
	return RegistryResponse{}, nil
}

func (f *FakeClient) GetRegistryByName(ctx context.Context, name string) (RegistryResponse, error) {
	if f.GetRegistryByNameFn != nil {
		return f.GetRegistryByNameFn(ctx, name)
	}
	return RegistryResponse{}, nil
}

func (f *FakeClient) CreateRegistry(ctx context.Context, body CreateRegistryInputBody) (CreateRegistryResponseBody, error) {
	if f.CreateRegistryFn != nil {
		return f.CreateRegistryFn(ctx, body)
	}
	return CreateRegistryResponseBody{}, nil
}

func (f *FakeClient) UpdateRegistry(ctx context.Context, id string, body UpdateRegistryInputBody) (RegistryResponse, error) {
	if f.UpdateRegistryFn != nil {
		return f.UpdateRegistryFn(ctx, id, body)
	}
	return RegistryResponse{}, nil
}

func (f *FakeClient) DeleteRegistry(ctx context.Context, id string) error {
	if f.DeleteRegistryFn != nil {
		return f.DeleteRegistryFn(ctx, id)
	}
	return nil
}

func (f *FakeClient) ScanRegistry(ctx context.Context, id string) (ScanRegistryOutputBody, error) {
	if f.ScanRegistryFn != nil {
		return f.ScanRegistryFn(ctx, id)
	}
	return ScanRegistryOutputBody{}, nil
}

func (f *FakeClient) TestRegistryConnection(ctx context.Context, body TestRegistryConnectionInputBody) (TestRegistryConnectionOutputBody, error) {
	if f.TestRegistryConnectionFn != nil {
		return f.TestRegistryConnectionFn(ctx, body)
	}
	return TestRegistryConnectionOutputBody{}, nil
}

func (f *FakeClient) RegenerateWebhookSecret(ctx context.Context, id string) (RegenerateWebhookSecretOutputBody, error) {
	if f.RegenerateWebhookSecretFn != nil {
		return f.RegenerateWebhookSecretFn(ctx, id)
	}
	return RegenerateWebhookSecretOutputBody{}, nil
}

func (f *FakeClient) CreateAPIKey(ctx context.Context, body CreateAPIKeyInputBody) (CreateAPIKeyOutputBody, error) {
	if f.CreateAPIKeyFn != nil {
		return f.CreateAPIKeyFn(ctx, body)
	}
	return CreateAPIKeyOutputBody{}, nil
}

func (f *FakeClient) ListAPIKeys(ctx context.Context) ([]KeyMetaResponse, error) {
	if f.ListAPIKeysFn != nil {
		return f.ListAPIKeysFn(ctx)
	}
	return nil, nil
}

func (f *FakeClient) DeleteAPIKey(ctx context.Context, id string) error {
	if f.DeleteAPIKeyFn != nil {
		return f.DeleteAPIKeyFn(ctx, id)
	}
	return nil
}

func (f *FakeClient) GetCurrentUser(ctx context.Context) (MeOutputBody, error) {
	if f.GetCurrentUserFn != nil {
		return f.GetCurrentUserFn(ctx)
	}
	return MeOutputBody{}, nil
}

func (f *FakeClient) IngestSBOM(ctx context.Context, data []byte, params IngestSbomParams) (IngestSBOMOutputBody, error) {
	if f.IngestSBOMFn != nil {
		return f.IngestSBOMFn(ctx, data, params)
	}
	return IngestSBOMOutputBody{}, nil
}

func (f *FakeClient) GetSBOM(ctx context.Context, id string, includeRaw bool) (SBOMDetail, error) {
	if f.GetSBOMFn != nil {
		return f.GetSBOMFn(ctx, id, includeRaw)
	}
	return SBOMDetail{}, nil
}

func (f *FakeClient) ListSBOMs(ctx context.Context, filter SBOMFilter, opts PageOpts) (CursorPage[SBOMSummary], error) {
	if f.ListSBOMsFn != nil {
		return f.ListSBOMsFn(ctx, filter, opts)
	}
	return CursorPage[SBOMSummary]{}, nil
}

func (f *FakeClient) DeleteSBOM(ctx context.Context, id string) error {
	if f.DeleteSBOMFn != nil {
		return f.DeleteSBOMFn(ctx, id)
	}
	return nil
}

func (f *FakeClient) DiffSBOMs(ctx context.Context, fromID, toID string) (ChangelogEntry, error) {
	if f.DiffSBOMsFn != nil {
		return f.DiffSBOMsFn(ctx, fromID, toID)
	}
	return ChangelogEntry{}, nil
}

func (f *FakeClient) GetDiffTree(ctx context.Context, fromID, toID string) (DiffTree, error) {
	if f.GetDiffTreeFn != nil {
		return f.GetDiffTreeFn(ctx, fromID, toID)
	}
	return DiffTree{}, nil
}

func (f *FakeClient) ListArtifacts(ctx context.Context, filter ArtifactFilter, opts PageOpts) (CursorPage[ArtifactSummary], error) {
	if f.ListArtifactsFn != nil {
		return f.ListArtifactsFn(ctx, filter, opts)
	}
	return CursorPage[ArtifactSummary]{}, nil
}

func (f *FakeClient) GetArtifact(ctx context.Context, id string) (ArtifactDetail, error) {
	if f.GetArtifactFn != nil {
		return f.GetArtifactFn(ctx, id)
	}
	return ArtifactDetail{}, nil
}

func (f *FakeClient) GetArtifactChangelog(ctx context.Context, id string, params GetArtifactChangelogParams) (Changelog, error) {
	if f.GetArtifactChangelogFn != nil {
		return f.GetArtifactChangelogFn(ctx, id, params)
	}
	return Changelog{}, nil
}

func (f *FakeClient) GetArtifactLicenseSummary(ctx context.Context, id string) (GetArtifactLicenseSummaryOutputBody, error) {
	if f.GetArtifactLicenseSummaryFn != nil {
		return f.GetArtifactLicenseSummaryFn(ctx, id)
	}
	return GetArtifactLicenseSummaryOutputBody{}, nil
}

func (f *FakeClient) ListArtifactSBOMs(ctx context.Context, id string, opts PageOpts) (CursorPage[SBOMSummary], error) {
	if f.ListArtifactSBOMsFn != nil {
		return f.ListArtifactSBOMsFn(ctx, id, opts)
	}
	return CursorPage[SBOMSummary]{}, nil
}

func (f *FakeClient) ListArtifactVersions(ctx context.Context, id string, opts PageOpts) (Page[ArtifactVersionSummary], error) {
	if f.ListArtifactVersionsFn != nil {
		return f.ListArtifactVersionsFn(ctx, id, opts)
	}
	return Page[ArtifactVersionSummary]{}, nil
}

func (f *FakeClient) LookupArtifact(ctx context.Context, params LookupArtifactParams) (ArtifactDetail, error) {
	if f.LookupArtifactFn != nil {
		return f.LookupArtifactFn(ctx, params)
	}
	return ArtifactDetail{}, nil
}

func (f *FakeClient) LookupSBOM(ctx context.Context, params LookupSbomParams) (SBOMDetail, error) {
	if f.LookupSBOMFn != nil {
		return f.LookupSBOMFn(ctx, params)
	}
	return SBOMDetail{}, nil
}

func (f *FakeClient) LookupLicense(ctx context.Context, spdxID string) (LicenseCount, error) {
	if f.LookupLicenseFn != nil {
		return f.LookupLicenseFn(ctx, spdxID)
	}
	return LicenseCount{}, nil
}

func (f *FakeClient) GetArtifactVulnSummary(ctx context.Context, artifactID string) (VulnSummary, error) {
	if f.GetArtifactVulnSummaryFn != nil {
		return f.GetArtifactVulnSummaryFn(ctx, artifactID)
	}
	return VulnSummary{}, nil
}

func (f *FakeClient) GetComponentVulns(ctx context.Context, componentID string) ([]ComponentVulnEntry, error) {
	if f.GetComponentVulnsFn != nil {
		return f.GetComponentVulnsFn(ctx, componentID)
	}
	return nil, nil
}

func (f *FakeClient) GetVulnerability(ctx context.Context, vulnID string, opts PageOpts) (GetVulnerabilityOutputBody, error) {
	if f.GetVulnerabilityFn != nil {
		return f.GetVulnerabilityFn(ctx, vulnID, opts)
	}
	return GetVulnerabilityOutputBody{}, nil
}

func (f *FakeClient) SearchComponents(ctx context.Context, filter ComponentFilter, opts PageOpts) (Page[ComponentSummary], error) {
	if f.SearchComponentsFn != nil {
		return f.SearchComponentsFn(ctx, filter, opts)
	}
	return Page[ComponentSummary]{}, nil
}

func (f *FakeClient) SearchDistinctComponents(ctx context.Context, filter DistinctComponentFilter, opts PageOpts) (Page[DistinctComponentSummary], error) {
	if f.SearchDistinctComponentsFn != nil {
		return f.SearchDistinctComponentsFn(ctx, filter, opts)
	}
	return Page[DistinctComponentSummary]{}, nil
}

func (f *FakeClient) GetComponent(ctx context.Context, id string) (ComponentDetail, error) {
	if f.GetComponentFn != nil {
		return f.GetComponentFn(ctx, id)
	}
	return ComponentDetail{}, nil
}

func (f *FakeClient) GetComponentVersions(ctx context.Context, params GetComponentVersionsParams) (GetComponentVersionsOutputBody, error) {
	if f.GetComponentVersionsFn != nil {
		return f.GetComponentVersionsFn(ctx, params)
	}
	return GetComponentVersionsOutputBody{}, nil
}

func (f *FakeClient) ListComponentPurlTypes(ctx context.Context) ([]string, error) {
	if f.ListComponentPurlTypesFn != nil {
		return f.ListComponentPurlTypesFn(ctx)
	}
	return nil, nil
}

func (f *FakeClient) ListSBOMComponents(ctx context.Context, sbomID string) ([]ComponentSummary, error) {
	if f.ListSBOMComponentsFn != nil {
		return f.ListSBOMComponentsFn(ctx, sbomID)
	}
	return nil, nil
}

func (f *FakeClient) GetSBOMDependencies(ctx context.Context, sbomID string) (DependencyGraph, error) {
	if f.GetSBOMDependenciesFn != nil {
		return f.GetSBOMDependenciesFn(ctx, sbomID)
	}
	return DependencyGraph{}, nil
}

func (f *FakeClient) ListJobs(ctx context.Context, filter JobFilter, opts PageOpts) (Page[ScanJobResponse], error) {
	if f.ListJobsFn != nil {
		return f.ListJobsFn(ctx, filter, opts)
	}
	return Page[ScanJobResponse]{}, nil
}

func (f *FakeClient) RetryJob(ctx context.Context, id string) error {
	if f.RetryJobFn != nil {
		return f.RetryJobFn(ctx, id)
	}
	return nil
}

func (f *FakeClient) GetJob(ctx context.Context, id string) (ScanJobResponse, error) {
	if f.GetJobFn != nil {
		return f.GetJobFn(ctx, id)
	}
	return ScanJobResponse{}, nil
}

func (f *FakeClient) GetDashboardStats(ctx context.Context) (DashboardStatsOutputBody, error) {
	if f.GetDashboardStatsFn != nil {
		return f.GetDashboardStatsFn(ctx)
	}
	return DashboardStatsOutputBody{}, nil
}

func (f *FakeClient) ListNamespaces(ctx context.Context) ([]NamespaceResponse, error) {
	if f.ListNamespacesFn != nil {
		return f.ListNamespacesFn(ctx)
	}
	return nil, nil
}

func (f *FakeClient) GetNamespace(ctx context.Context, id string) (NamespaceResponse, error) {
	if f.GetNamespaceFn != nil {
		return f.GetNamespaceFn(ctx, id)
	}
	return NamespaceResponse{}, nil
}

func (f *FakeClient) GetNamespaceByName(ctx context.Context, name string) (NamespaceResponse, error) {
	if f.GetNamespaceByNameFn != nil {
		return f.GetNamespaceByNameFn(ctx, name)
	}
	return NamespaceResponse{}, nil
}

func (f *FakeClient) CreateNamespace(ctx context.Context, body CreateNamespaceInputBody) (NamespaceResponse, error) {
	if f.CreateNamespaceFn != nil {
		return f.CreateNamespaceFn(ctx, body)
	}
	return NamespaceResponse{}, nil
}

func (f *FakeClient) UpdateNamespace(ctx context.Context, id string, body UpdateNamespaceInputBody) (NamespaceResponse, error) {
	if f.UpdateNamespaceFn != nil {
		return f.UpdateNamespaceFn(ctx, id, body)
	}
	return NamespaceResponse{}, nil
}

func (f *FakeClient) DeleteNamespace(ctx context.Context, id string) error {
	if f.DeleteNamespaceFn != nil {
		return f.DeleteNamespaceFn(ctx, id)
	}
	return nil
}

func (f *FakeClient) ListSources(ctx context.Context, namespaceID string) ([]SourceResponse, error) {
	if f.ListSourcesFn != nil {
		return f.ListSourcesFn(ctx, namespaceID)
	}
	return nil, nil
}

func (f *FakeClient) GetSource(ctx context.Context, id string) (SourceResponse, error) {
	if f.GetSourceFn != nil {
		return f.GetSourceFn(ctx, id)
	}
	return SourceResponse{}, nil
}

func (f *FakeClient) CreateSource(ctx context.Context, body CreateSourceInputBody) (SourceResponse, error) {
	if f.CreateSourceFn != nil {
		return f.CreateSourceFn(ctx, body)
	}
	return SourceResponse{}, nil
}

func (f *FakeClient) UpdateSource(ctx context.Context, id string, body UpdateSourceInputBody) (SourceResponse, error) {
	if f.UpdateSourceFn != nil {
		return f.UpdateSourceFn(ctx, id, body)
	}
	return SourceResponse{}, nil
}

func (f *FakeClient) DeleteSource(ctx context.Context, id string) error {
	if f.DeleteSourceFn != nil {
		return f.DeleteSourceFn(ctx, id)
	}
	return nil
}

func (f *FakeClient) ListClusters(ctx context.Context, namespaceID string) ([]ClusterResponse, error) {
	if f.ListClustersFn != nil {
		return f.ListClustersFn(ctx, namespaceID)
	}
	return nil, nil
}

func (f *FakeClient) GetCluster(ctx context.Context, id string) (ClusterResponse, error) {
	if f.GetClusterFn != nil {
		return f.GetClusterFn(ctx, id)
	}
	return ClusterResponse{}, nil
}

func (f *FakeClient) CreateCluster(ctx context.Context, body CreateClusterInputBody) (ClusterResponse, error) {
	if f.CreateClusterFn != nil {
		return f.CreateClusterFn(ctx, body)
	}
	return ClusterResponse{}, nil
}

func (f *FakeClient) UpdateCluster(ctx context.Context, id string, body UpdateClusterInputBody) (ClusterResponse, error) {
	if f.UpdateClusterFn != nil {
		return f.UpdateClusterFn(ctx, id, body)
	}
	return ClusterResponse{}, nil
}

func (f *FakeClient) DeleteCluster(ctx context.Context, id string) error {
	if f.DeleteClusterFn != nil {
		return f.DeleteClusterFn(ctx, id)
	}
	return nil
}

func (f *FakeClient) PutInventory(ctx context.Context, clusterID string, workloads []InventoryWorkload) (PutInventoryOutputBody, error) {
	if f.PutInventoryFn != nil {
		return f.PutInventoryFn(ctx, clusterID, workloads)
	}
	return PutInventoryOutputBody{}, nil
}

func (f *FakeClient) ListClusterWorkloads(ctx context.Context, clusterID string) ([]ClusterWorkloadResponse, WorkloadCoverageResponse, error) {
	if f.ListClusterWorkloadsFn != nil {
		return f.ListClusterWorkloadsFn(ctx, clusterID)
	}
	return nil, WorkloadCoverageResponse{}, nil
}

// Compile-time assertion that *FakeClient satisfies Client.
var _ Client = (*FakeClient)(nil)

func (f *FakeClient) GetOpenAPISpec(ctx context.Context) (json.RawMessage, error) {
	if f.GetOpenAPISpecFn != nil {
		return f.GetOpenAPISpecFn(ctx)
	}
	return nil, nil
}
