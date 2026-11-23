// Consumer-sized views of the services. Each interface names
// only what the handlers call, grouped by area, so an endpoint test fakes a few
// methods instead of a 42-method SearchService. The concrete services satisfy
// them all; cmd/ocidex hands the same service to every view of it.

package api

import (
	"context"
	"time"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// SBOMReader reads SBOMs, their components and vulnerabilities, and diffs between them.
type SBOMReader interface {
	GetSBOM(ctx context.Context, id string, includeRaw bool, vis service.VisibilityFilter) (service.SBOMDetail, error)
	ListSBOMs(ctx context.Context, filter service.SBOMFilter) (service.CursorPage[service.SBOMSummary], error)
	LookupSBOM(ctx context.Context, query service.SBOMLookupQuery, vis service.VisibilityFilter) ([]service.LookupCandidate, error)
	GetSBOMDependencies(ctx context.Context, sbomID string, vis service.VisibilityFilter) (service.DependencyGraph, error)
	ListSBOMComponentsPage(ctx context.Context, sbomID string, page service.ComponentPage, vis service.VisibilityFilter) (service.CursorPage[service.ComponentSummary], error)
	ListSBOMVulns(ctx context.Context, sbomID string, params service.SBOMVulnParams, vis service.VisibilityFilter) (service.PagedResult[service.SBOMVulnEntry], error)
	ListSBOMDriftHistory(ctx context.Context, sbomID string, page service.DriftPage, vis service.VisibilityFilter) (service.CursorPage[service.ProvenanceDriftSummary], error)
	DiffSBOMs(ctx context.Context, fromID, toID string, vis service.VisibilityFilter) (service.ChangelogEntry, error)
	DiffSBOMsWithTree(ctx context.Context, fromID, toID string, vis service.VisibilityFilter) (service.DiffTree, error)
}

// ComponentReader searches components and licenses.
type ComponentReader interface {
	SearchComponents(ctx context.Context, filter service.ComponentFilter) (service.PagedResult[service.ComponentSummary], error)
	SearchDistinctComponents(ctx context.Context, filter service.ComponentFilter) (service.PagedResult[service.DistinctComponentSummary], error)
	GetComponent(ctx context.Context, id string, vis service.VisibilityFilter) (service.ComponentDetail, error)
	GetComponentVersions(ctx context.Context, filter service.ComponentVersionFilter) (service.ComponentVersionsPage, error)
	ListComponentVersionSummaries(ctx context.Context, filter service.ComponentVersionFilter) (service.ComponentVersionSummaryPage, error)
	ListComponentPurlTypes(ctx context.Context, vis service.VisibilityFilter) ([]string, error)
	GetComponentVulns(ctx context.Context, id string, vis service.VisibilityFilter) ([]service.ComponentVulnEntry, error)
	ListLicenses(ctx context.Context, filter service.LicenseFilter) (service.PagedResult[service.LicenseCount], error)
	ListComponentsByLicense(ctx context.Context, licenseID string, limit, offset int32, vis service.VisibilityFilter) (service.PagedResult[service.ComponentSummary], error)
	LookupLicense(ctx context.Context, spdxID string, vis service.VisibilityFilter) (service.LicenseCount, error)
}

// ArtifactReader reads artifacts and their versions.
type ArtifactReader interface {
	GetArtifact(ctx context.Context, id string, vis service.VisibilityFilter) (service.ArtifactDetail, error)
	ListArtifacts(ctx context.Context, filter service.ArtifactFilter) (service.CursorPage[service.ArtifactSummary], error)
	CountArtifacts(ctx context.Context, filter service.ArtifactFilter) (int64, error)
	LookupArtifact(ctx context.Context, query service.ArtifactLookupQuery, vis service.VisibilityFilter) ([]service.LookupCandidate, error)
	ResolveArtifactEntryNumber(ctx context.Context, entryNumber int64, vis service.VisibilityFilter) (string, error)
	ListSBOMsByArtifact(ctx context.Context, artifactID string, subjectVersion, imageVersion string, page service.SBOMByArtifactPage, vis service.VisibilityFilter) (service.CursorPage[service.SBOMSummary], error)
	ListVersionsByArtifact(ctx context.Context, artifactID string, limit, offset int32, mode service.VersionSortMode, colSort service.VersionColumnSort, vis service.VisibilityFilter) (service.ArtifactVersionsPage, error)
	GetArtifactChangelog(ctx context.Context, artifactID string, query service.ChangelogQuery, vis service.VisibilityFilter) (service.Changelog, error)
}

// ArtifactInsights summarizes an artifact's licenses, vulnerabilities and relations.
type ArtifactInsights interface {
	GetArtifactLicenseSummary(ctx context.Context, artifactID string, vis service.VisibilityFilter) (service.ArtifactLicenseSummary, error)
	GetArtifactVulnSummary(ctx context.Context, artifactID string, vis service.VisibilityFilter) (service.ArtifactVulnSummary, error)
	GetArtifactUsages(ctx context.Context, artifactID string, vis service.VisibilityFilter) ([]service.ArtifactRelation, error)
	GetArtifactContains(ctx context.Context, artifactID string, vis service.VisibilityFilter) ([]service.ArtifactRelation, error)
	ListArtifactVulns(ctx context.Context, artifactID string, params service.ArtifactVulnParams, vis service.VisibilityFilter) (service.ArtifactVulnPage, error)
}

// InsightReader serves the dashboard, discovery and vulnerability views.
type InsightReader interface {
	GetDashboardStats(ctx context.Context, vis service.VisibilityFilter) (*service.DashboardStats, error)
	GetDiscovery(ctx context.Context) (*service.Discovery, error)
	ListTopVulnerabilities(ctx context.Context, filter service.TopVulnFilter) (service.PagedResult[service.TopVulnEntry], error)
	GetVulnerabilityDetail(ctx context.Context, id string, limit, offset int32, allVersions bool, vis service.VisibilityFilter) (service.VulnerabilityDetailResult, error)
	VulnDBBuiltAt(ctx context.Context) (*time.Time, error)
	ListRecentProvenanceDrift(ctx context.Context, page service.DriftPage, vis service.VisibilityFilter) (service.CursorPage[service.RecentDriftEntry], error)
	ListOwnedActivity(ctx context.Context, ownerID string, keyNamespaces []string, page service.FeedPage) (service.CursorPage[service.ActivityEntry], error)
}

// Authenticator checks the credential a request presents.
type Authenticator interface {
	ValidateAPIKey(ctx context.Context, rawKey string) (service.AuthUser, error)
	ValidateSession(ctx context.Context, token string) (service.AuthUser, error)
	LoadGrants(ctx context.Context, userID string) (map[string]authz.Role, error)
}

// LoginFlow signs users in and out and links their identities.
type LoginFlow interface {
	ProviderNames() []string
	BuildAuthURL(provider, state, verifier string) (string, error)
	ExchangeCodeForUser(ctx context.Context, provider, code, verifier string) (service.AuthUser, error)
	CreateSession(ctx context.Context, userID string) (plaintext string, err error)
	DeleteSession(ctx context.Context, token string) error
	ListIdentities(ctx context.Context, userID string) ([]service.LinkedIdentity, error)
	LinkIdentity(ctx context.Context, userID string, provider, code, verifier string) (service.LinkedIdentity, error)
	UnlinkIdentity(ctx context.Context, userID string, identityID string) error
}

// AccountAdmin manages users and their API keys.
type AccountAdmin interface {
	CreateKey(ctx context.Context, userID string, spec service.KeySpec) (plaintext string, err error)
	CreateExpiringAPIKey(ctx context.Context, userID string, name string, caps []authz.Capability, expiresAt time.Time) (plaintext string, err error)
	ListAPIKeys(ctx context.Context, userID string) ([]service.APIKeyMeta, error)
	DeleteAPIKey(ctx context.Context, userID string, keyID string) error
	GetUser(ctx context.Context, userID string) (service.AuthUser, error)
	ListUsers(ctx context.Context) ([]service.AuthUser, error)
	UpdateUserRole(ctx context.Context, targetID string, role string) (service.AuthUser, error)
}

// RegistryStore reads and changes registries, and records their walks.
type RegistryStore interface {
	Create(ctx context.Context, params service.CreateRegistryParams) (service.Registry, error)
	Get(ctx context.Context, id string) (service.Registry, error)
	GetByName(ctx context.Context, name string) (service.Registry, error)
	ListPaged(ctx context.Context, filter service.VisibilityFilter, limit, offset int32) (service.PagedResult[service.Registry], error)
	Update(ctx context.Context, params service.UpdateRegistryParams) (service.Registry, error)
	Delete(ctx context.Context, id string) error
	MoveNamespace(ctx context.Context, id, namespaceID string) error
	TrustSummary(ctx context.Context, vis service.VisibilityFilter) ([]service.RegistryTrustCount, error)
	RecordWalkStats(ctx context.Context, id string, stats service.WalkStats) error
}

// JobAdmin lists and retries scan jobs.
type JobAdmin interface {
	List(ctx context.Context, state string, vis service.VisibilityFilter, limit, offset int32) ([]service.ScanJob, int64, error)
	Get(ctx context.Context, id string, vis service.VisibilityFilter) (service.ScanJob, error)
	CountByState(ctx context.Context) (queued, running, succeeded24h, failed24h int64, err error)
	Retry(ctx context.Context, id string) error
	RetryAllFailed(ctx context.Context) (int64, error)
	Cancel(ctx context.Context, id string) error
}

// ClusterAdmin manages clusters.
type ClusterAdmin interface {
	Create(ctx context.Context, params service.CreateClusterParams) (service.Cluster, error)
	Get(ctx context.Context, id string) (service.Cluster, error)
	List(ctx context.Context, filter service.VisibilityFilter) ([]service.Cluster, error)
	ListByNamespace(ctx context.Context, namespaceID string) ([]service.Cluster, error)
	Update(ctx context.Context, params service.UpdateClusterParams) (service.Cluster, error)
	Delete(ctx context.Context, id string) error
	Connect(ctx context.Context, p service.ConnectClusterParams) (service.Cluster, service.ClusterCredential, error)
}

// ClusterAgent takes a cluster agent's inventory pushes and manages its credentials.
type ClusterAgent interface {
	ReplaceInventory(ctx context.Context, clusterID string, workloads []service.ReportedWorkload, agent *service.AgentInfo) (int, error)
	RecordPush(ctx context.Context, clusterID string, p service.PushAttempt) error
	ListPushes(ctx context.Context, clusterID string, limit int32) ([]service.ClusterPush, error)
	CreateCredential(ctx context.Context, clusterID string, userID string, name string) (service.ClusterCredential, error)
	ListCredentials(ctx context.Context, clusterID string) ([]service.ClusterCredential, error)
	RevokeCredential(ctx context.Context, clusterID, credentialID string) error
	RotateCredential(ctx context.Context, clusterID, credentialID string, userID string) (service.ClusterCredential, error)
}

// ClusterInventory reads what a cluster runs and ingests what it hasn't scanned.
type ClusterInventory interface {
	ListWorkloads(ctx context.Context, clusterID string, params service.WorkloadParams, filter service.VisibilityFilter) (service.PagedResult[service.ClusterWorkload], error)
	ListImages(ctx context.Context, clusterID string, params service.ImageParams, filter service.VisibilityFilter) (service.PagedResult[service.ClusterImage], error)
	NamespaceFacets(ctx context.Context, clusterID string, filter service.VisibilityFilter) ([]service.NamespaceFacet, error)
	Coverage(ctx context.Context, clusterID string, filter service.VisibilityFilter) (service.WorkloadCoverage, error)
	RunningVulns(ctx context.Context, clusterID string, params service.RunningVulnParams, filter service.VisibilityFilter) (service.PagedResult[service.RunningVuln], error)
	WorkloadsForVulnerability(ctx context.Context, canonicalID, clusterID string, limit int32, filter service.VisibilityFilter) ([]service.RunningWorkload, error)
	WorkloadsForArtifact(ctx context.Context, artifactID string, limit int32, filter service.VisibilityFilter) ([]service.RunningWorkload, error)
	RegistryGaps(ctx context.Context, filter service.VisibilityFilter) ([]service.RegistryClusterGap, error)
	UnknownImages(ctx context.Context, clusterID string, limit, offset int32, filter service.VisibilityFilter) (service.UnknownImagesPage, error)
	IngestUnknown(ctx context.Context, clusterID string, sub service.RunningImageSubmitter, params service.IngestUnknownParams, filter service.VisibilityFilter) (service.IngestResult, error)
}
