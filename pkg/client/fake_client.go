package client

import "context"

// FakeClient is a test double that implements Client.
// Set function fields to stub individual methods; unset fields return zero values and nil error.
type FakeClient struct {
	// Registry + auth
	ListRegistriesFn          func(ctx context.Context, opts PageOpts) (Page[RegistryResponse], error)
	GetRegistryFn             func(ctx context.Context, id string) (RegistryResponse, error)
	CreateRegistryFn          func(ctx context.Context, body CreateRegistryInputBody) (CreateRegistryResponseBody, error)
	UpdateRegistryFn          func(ctx context.Context, id string, body UpdateRegistryInputBody) (RegistryResponse, error)
	DeleteRegistryFn          func(ctx context.Context, id string) error
	ScanRegistryFn            func(ctx context.Context, id string) (ScanRegistryOutputBody, error)
	TestRegistryConnectionFn  func(ctx context.Context, body TestRegistryConnectionInputBody) (TestRegistryConnectionOutputBody, error)
	RegenerateWebhookSecretFn func(ctx context.Context, id string) (RegenerateWebhookSecretOutputBody, error)

	CreateAPIKeyFn   func(ctx context.Context, body CreateAPIKeyInputBody) (CreateAPIKeyOutputBody, error)
	ListAPIKeysFn    func(ctx context.Context) ([]KeyMetaResponse, error)
	DeleteAPIKeyFn   func(ctx context.Context, id string) error
	GetCurrentUserFn func(ctx context.Context) (MeOutputBody, error)

	// SBOM + artifact
	IngestSBOMFn                func(ctx context.Context, data []byte, params IngestSbomParams) (IngestSBOMOutputBody, error)
	GetSBOMFn                   func(ctx context.Context, id string, includeRaw bool) (SBOMDetail, error)
	ListSBOMsFn                 func(ctx context.Context, opts PageOpts) (CursorPage[SBOMSummary], error)
	DeleteSBOMFn                func(ctx context.Context, id string) error
	DiffSBOMsFn                 func(ctx context.Context, fromID, toID string) (ChangelogEntry, error)
	GetDiffTreeFn               func(ctx context.Context, fromID, toID string) (DiffTree, error)
	ListArtifactsFn             func(ctx context.Context, opts PageOpts) (CursorPage[ArtifactSummary], error)
	GetArtifactFn               func(ctx context.Context, id string) (ArtifactDetail, error)
	GetArtifactChangelogFn      func(ctx context.Context, id string, params GetArtifactChangelogParams) (Changelog, error)
	GetArtifactLicenseSummaryFn func(ctx context.Context, id string) (GetArtifactLicenseSummaryOutputBody, error)
	ListArtifactSBOMsFn         func(ctx context.Context, id string, opts PageOpts) (CursorPage[SBOMSummary], error)
	ListArtifactVersionsFn      func(ctx context.Context, id string, opts PageOpts) (Page[ArtifactVersionSummary], error)

	// Component + job + stats
	SearchComponentsFn         func(ctx context.Context, query string, opts PageOpts) (Page[ComponentSummary], error)
	SearchDistinctComponentsFn func(ctx context.Context, query string, opts PageOpts) (Page[DistinctComponentSummary], error)
	GetComponentFn             func(ctx context.Context, id string) (ComponentDetail, error)
	GetComponentVersionsFn     func(ctx context.Context, params GetComponentVersionsParams) (GetComponentVersionsOutputBody, error)
	ListComponentPurlTypesFn   func(ctx context.Context) ([]string, error)
	ListSBOMComponentsFn       func(ctx context.Context, sbomID string) ([]ComponentSummary, error)
	GetSBOMDependenciesFn      func(ctx context.Context, sbomID string) (DependencyGraph, error)

	ListJobsFn          func(ctx context.Context, opts PageOpts) (Page[ScanJobResponse], error)
	GetJobFn            func(ctx context.Context, id string) (ScanJobResponse, error)
	GetDashboardStatsFn func(ctx context.Context) (DashboardStatsOutputBody, error)
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

func (f *FakeClient) ListSBOMs(ctx context.Context, opts PageOpts) (CursorPage[SBOMSummary], error) {
	if f.ListSBOMsFn != nil {
		return f.ListSBOMsFn(ctx, opts)
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

func (f *FakeClient) ListArtifacts(ctx context.Context, opts PageOpts) (CursorPage[ArtifactSummary], error) {
	if f.ListArtifactsFn != nil {
		return f.ListArtifactsFn(ctx, opts)
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

func (f *FakeClient) SearchComponents(ctx context.Context, query string, opts PageOpts) (Page[ComponentSummary], error) {
	if f.SearchComponentsFn != nil {
		return f.SearchComponentsFn(ctx, query, opts)
	}
	return Page[ComponentSummary]{}, nil
}

func (f *FakeClient) SearchDistinctComponents(ctx context.Context, query string, opts PageOpts) (Page[DistinctComponentSummary], error) {
	if f.SearchDistinctComponentsFn != nil {
		return f.SearchDistinctComponentsFn(ctx, query, opts)
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

func (f *FakeClient) ListJobs(ctx context.Context, opts PageOpts) (Page[ScanJobResponse], error) {
	if f.ListJobsFn != nil {
		return f.ListJobsFn(ctx, opts)
	}
	return Page[ScanJobResponse]{}, nil
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

// Compile-time assertion that *FakeClient satisfies Client.
var _ Client = (*FakeClient)(nil)
