package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pfenerty/ocidex/internal/repository"
)

// SearchService defines read-only operations for SBOM search and retrieval.
type SearchService interface {
	GetSBOM(ctx context.Context, id pgtype.UUID, includeRaw bool, vis VisibilityFilter) (SBOMDetail, error)
	ListSBOMs(ctx context.Context, filter SBOMFilter) (CursorPage[SBOMSummary], error)
	SearchComponents(ctx context.Context, filter ComponentFilter) (PagedResult[ComponentSummary], error)
	SearchDistinctComponents(ctx context.Context, filter ComponentFilter) (PagedResult[DistinctComponentSummary], error)
	GetComponentVersions(ctx context.Context, filter ComponentVersionFilter) (ComponentVersionsPage, error)
	GetComponent(ctx context.Context, id pgtype.UUID, vis VisibilityFilter) (ComponentDetail, error)
	ListLicenses(ctx context.Context, filter LicenseFilter) (PagedResult[LicenseCount], error)
	ListComponentsByLicense(ctx context.Context, licenseID pgtype.UUID, limit, offset int32, vis VisibilityFilter) (PagedResult[ComponentSummary], error)
	GetArtifact(ctx context.Context, id pgtype.UUID, vis VisibilityFilter) (ArtifactDetail, error)
	ListArtifacts(ctx context.Context, filter ArtifactFilter) (CursorPage[ArtifactSummary], error)
	ListSBOMsByArtifact(ctx context.Context, artifactID pgtype.UUID, subjectVersion, imageVersion string, page SBOMByArtifactPage, vis VisibilityFilter) (CursorPage[SBOMSummary], error)
	ListVersionsByArtifact(ctx context.Context, artifactID pgtype.UUID, limit, offset int32, mode VersionSortMode, colSort VersionColumnSort, vis VisibilityFilter) (ArtifactVersionsPage, error)
	GetArtifactChangelog(ctx context.Context, artifactID pgtype.UUID, subjectVersion, arch, flavor string, mode VersionSortMode, vis VisibilityFilter) (Changelog, error)
	DiffSBOMs(ctx context.Context, fromID, toID pgtype.UUID, vis VisibilityFilter) (ChangelogEntry, error)
	DiffSBOMsWithTree(ctx context.Context, fromID, toID pgtype.UUID, vis VisibilityFilter) (DiffTree, error)
	ListSBOMsByDigest(ctx context.Context, digest string, limit, offset int32, vis VisibilityFilter) (PagedResult[SBOMSummary], error)
	GetArtifactLicenseSummary(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) ([]LicenseCount, error)
	GetSBOMDependencies(ctx context.Context, sbomID pgtype.UUID, vis VisibilityFilter) (DependencyGraph, error)
	ListSBOMComponents(ctx context.Context, sbomID pgtype.UUID, vis VisibilityFilter) ([]ComponentSummary, error)
	ListSBOMComponentsPage(ctx context.Context, sbomID pgtype.UUID, page ComponentPage, vis VisibilityFilter) (CursorPage[ComponentSummary], error)
	ListComponentPurlTypes(ctx context.Context, vis VisibilityFilter) ([]string, error)
	GetDashboardStats(ctx context.Context, vis VisibilityFilter) (*DashboardStats, error)
	WarmDashboardStats(ctx context.Context, vis VisibilityFilter) (*DashboardStats, error)
	GetDiscovery(ctx context.Context) (*Discovery, error)
	WarmDiscovery(ctx context.Context) (*Discovery, error)
	ListTopVulnerabilities(ctx context.Context, filter TopVulnFilter) (PagedResult[TopVulnEntry], error)
	GetArtifactVulnSummary(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) (*VulnSummary, error)
	GetArtifactUsages(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) ([]ArtifactRelation, error)
	GetArtifactContains(ctx context.Context, artifactID pgtype.UUID, vis VisibilityFilter) ([]ArtifactRelation, error)
	GetVulnerabilityDetail(ctx context.Context, id string, limit, offset int32, vis VisibilityFilter) (VulnerabilityDetailResult, error)
	GetComponentVulns(ctx context.Context, id pgtype.UUID, vis VisibilityFilter) ([]ComponentVulnEntry, error)
	ListSBOMVulns(ctx context.Context, sbomID pgtype.UUID, params SBOMVulnParams, vis VisibilityFilter) (PagedResult[SBOMVulnEntry], error)
	ListArtifactVulns(ctx context.Context, artifactID pgtype.UUID, params ArtifactVulnParams, vis VisibilityFilter) (PagedResult[ArtifactVulnEntry], error)
	ListSBOMDriftHistory(ctx context.Context, sbomID pgtype.UUID, page DriftPage, vis VisibilityFilter) (CursorPage[ProvenanceDriftSummary], error)
	ListRecentProvenanceDrift(ctx context.Context, page DriftPage, vis VisibilityFilter) (CursorPage[RecentDriftEntry], error)
	ListOwnedActivity(ctx context.Context, ownerID pgtype.UUID, page FeedPage) (CursorPage[ActivityEntry], error)
	LookupArtifact(ctx context.Context, query ArtifactLookupQuery, vis VisibilityFilter) ([]LookupCandidate, error)
	LookupSBOM(ctx context.Context, query SBOMLookupQuery, vis VisibilityFilter) ([]LookupCandidate, error)
	LookupLicense(ctx context.Context, spdxID string, vis VisibilityFilter) (LicenseCount, error)
}

// RecentDriftEntry is a provenance_drift_events row enriched with enough
// SBOM/artifact/registry context to render in a cross-registry feed.
type RecentDriftEntry struct {
	ProvenanceDriftSummary
	SBOMID       string  `json:"sbomId"`
	RegistryID   *string `json:"registryId,omitempty"`
	RegistryName *string `json:"registryName,omitempty"`
	ArtifactID   *string `json:"artifactId,omitempty"`
	ArtifactName *string `json:"artifactName,omitempty"`
	ArtifactType *string `json:"artifactType,omitempty"`
}

// DashboardStats holds aggregated metrics for the dashboard.
type DashboardStats struct {
	ArtifactCount         int64
	SBOMCount             int64
	PackageCount          int64
	VersionCount          int64
	LicenseCount          int64
	ArtifactTypes         []ArtifactTypeCount
	LicenseCategories     []CategoryCount
	IngestionTimeline     []DailyCount
	PackageGrowthTimeline []DailyCount
	VersionGrowthTimeline []DailyCount
	TopPackages           []PackageSummary
	VulnCount             int64
	VulnSeverity          VulnSeverityBreakdown

	// Warming reports that no computed snapshot was available and every count
	// above is a zero placeholder. Clients must render their loading state
	// rather than "0 artifacts" — the stats are computed out-of-band by the
	// background warmer and appear on a later poll.
	Warming bool
}

// ArtifactTypeCount is the number of tracked artifacts of one CycloneDX type.
type ArtifactTypeCount struct {
	Type          string
	ArtifactCount int64
}

// VulnSeverityBreakdown is a per-severity count of distinct tracked vulnerabilities.
type VulnSeverityBreakdown struct {
	Critical int64
	High     int64
	Medium   int64
	Low      int64
	Unknown  int64
}

// TopVulnEntry is one item in the top-vulnerabilities list.
type TopVulnEntry struct {
	ID                string     `json:"id"`
	CanonicalID       string     `json:"canonicalId"`
	Severity          string     `json:"severity"`
	CvssScore         *float32   `json:"cvssScore,omitempty"`
	Summary           *string    `json:"summary,omitempty"`
	Aliases           []string   `json:"aliases"`
	PublishedAt       *time.Time `json:"publishedAt,omitempty"`
	AffectedSbomCount int64      `json:"affectedSbomCount"`
	AffectedPurlCount int64      `json:"affectedPurlCount"`
}

// TopVulnFilter holds parameters for listing top vulnerabilities.
type TopVulnFilter struct {
	Limit  int32
	Offset int32
	// IDQuery narrows the list to vulnerabilities whose canonical id or any
	// alias contains this substring. Empty means no narrowing.
	IDQuery    string
	Severity   string
	Sort       string
	SortDir    string
	Visibility VisibilityFilter
}

// VulnDetail is full vulnerability detail returned by GET /api/v1/vulns/{id}.
type VulnDetail struct {
	ID          string          `json:"id"`
	CanonicalID string          `json:"canonicalId"`
	Severity    string          `json:"severity"`
	CvssScore   *float32        `json:"cvssScore,omitempty"`
	CvssVector  *string         `json:"cvssVector,omitempty"`
	Summary     *string         `json:"summary,omitempty"`
	Details     *string         `json:"details,omitempty"`
	Aliases     []string        `json:"aliases"`
	References  []VulnReference `json:"references,omitempty"`
	PublishedAt *time.Time      `json:"publishedAt,omitempty"`
	ModifiedAt  *time.Time      `json:"modifiedAt,omitempty"`
}

// VulnReference is one external link associated with a vulnerability.
type VulnReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// AffectedArtifact is an artifact that contains a component affected by a vulnerability.
type AffectedArtifact struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Group             *string `json:"group,omitempty"`
	AffectedSbomCount int64   `json:"affectedSbomCount"`
	AffectedPurlCount int64   `json:"affectedPurlCount"`
}

// AffectedComponent is a distinct component (by name+group) affected by a vulnerability.
type AffectedComponent struct {
	Name                 string  `json:"name"`
	Group                *string `json:"group,omitempty"`
	FixedVersion         *string `json:"fixedVersion,omitempty"`
	AffectedVersionCount int64   `json:"affectedVersionCount"`
}

// ComponentVulnEntry is one vulnerability finding for a specific component purl.
type ComponentVulnEntry struct {
	ID           string   `json:"id"`
	CanonicalID  string   `json:"canonicalId"`
	Severity     string   `json:"severity"`
	CvssScore    *float32 `json:"cvssScore,omitempty"`
	Summary      *string  `json:"summary,omitempty"`
	FixedVersion *string  `json:"fixedVersion,omitempty"`
	// MatchedViaSource is true when this finding matched the component's
	// source package purl rather than the component's own purl.
	MatchedViaSource bool `json:"matchedViaSource"`
}

// SBOMVulnEntry is one row of an SBOM's vulnerability list. Rows are keyed by
// CanonicalID, not by the native OSV id, so an alias group (GO-… / GHSA-… /
// CVE-…) is one finding — the same dedupe GetSBOMVulnSummary applies, so the
// tile and the tab agree about what one row is.
type SBOMVulnEntry struct {
	ID          string   `json:"id"`
	CanonicalID string   `json:"canonicalId"`
	Severity    string   `json:"severity"`
	CvssScore   *float32 `json:"cvssScore,omitempty"`
	Summary     *string  `json:"summary,omitempty"`
	// AffectedPackageCount counts distinct component purls across the whole
	// alias group — a number to act on, not a count of finding rows.
	AffectedPackageCount int64 `json:"affectedPackageCount"`
	// AffectedPackages are the components this finding lands on, carried inline
	// so the tab's expandable rows need no second request.
	AffectedPackages []SBOMVulnPackage `json:"affectedPackages"`
}

// SBOMVulnPackage is one component a vulnerability affects inside an SBOM.
type SBOMVulnPackage struct {
	Purl         string  `json:"purl"`
	Name         string  `json:"name"`
	Group        *string `json:"group,omitempty"`
	Version      *string `json:"version,omitempty"`
	FixedVersion *string `json:"fixedVersion,omitempty"`
	// MatchedViaSource is true when the finding matched the component's source
	// package purl rather than its own — an inherited match, not a direct one.
	MatchedViaSource bool `json:"matchedViaSource"`
}

// SBOMVulnParams filters, sorts and pages ListSBOMVulns.
type SBOMVulnParams struct {
	Severity string // empty means every severity
	SortBy   string // one of SBOMVulnSortKeys; empty means the default
	SortDir  string // "asc" or "desc"; empty means "asc"
	Limit    int32
	Offset   int32
}

// SBOMVulnSortKeys are the columns ListSBOMVulns will order by. Anything else
// is dropped before it reaches the query's CASE, where an unmatched key would
// produce an arbitrary order that looks like a working sort.
var SBOMVulnSortKeys = map[string]bool{
	sortBySeverity:           true,
	sortByCVSS:               true,
	"affected_package_count": true,
	sortByCanonicalID:        true,
}

// ArtifactVulnEntry is one row of an artifact's vulnerability list. Same
// canonical_id keying as SBOMVulnEntry, one level up: the scope is the newest
// SBOM per version, so a row also carries how many of those versions it hits.
type ArtifactVulnEntry struct {
	ID                   string   `json:"id"`
	CanonicalID          string   `json:"canonicalId"`
	Severity             string   `json:"severity"`
	CvssScore            *float32 `json:"cvssScore,omitempty"`
	Summary              *string  `json:"summary,omitempty"`
	AffectedPackageCount int64    `json:"affectedPackageCount"`
	// AffectedVersionCount is how many of the artifact's versions carry this
	// finding. It is the reverse trail's answer: /vulnerabilities/{id} sends a
	// reader here asking "which versions of this artifact", and this is it.
	AffectedVersionCount int64 `json:"affectedVersionCount"`
	// AffectedVersions is attached inline for the page, so expanding a row
	// costs no second request.
	AffectedVersions []ArtifactVulnVersion `json:"affectedVersions"`
}

// ArtifactVulnVersion is one of an artifact's versions that a vulnerability
// reaches, with the SBOM that carries it so the row can link onward.
type ArtifactVulnVersion struct {
	Version              string   `json:"version"`
	SbomID               string   `json:"sbomId"`
	AffectedPackageCount int64    `json:"affectedPackageCount"`
	PackageNames         []string `json:"packageNames"`
}

// ArtifactVulnParams filters, sorts and pages ListArtifactVulns.
type ArtifactVulnParams struct {
	Severity string
	// Vuln pre-filters to a single advisory, matched against either the
	// canonical id or the native OSV id. This is what lets
	// /vulnerabilities/{id} link to the one row it is talking about.
	Vuln    string
	SortBy  string // one of ArtifactVulnSortKeys; empty means the default
	SortDir string
	Limit   int32
	Offset  int32
}

// ArtifactVulnSortKeys are the columns ListArtifactVulns will order by. As with
// SBOMVulnSortKeys, anything else is dropped before it reaches the query.
var ArtifactVulnSortKeys = map[string]bool{
	sortBySeverity:           true,
	sortByCVSS:               true,
	"affected_package_count": true,
	"affected_version_count": true,
	sortByCanonicalID:        true,
}

// PackageSummary is a distinct package with version and SBOM counts.
type PackageSummary struct {
	Name         string  `json:"name"`
	Group        *string `json:"group,omitempty"`
	Type         string  `json:"type"`
	VersionCount int64   `json:"versionCount"`
	SbomCount    int64   `json:"sbomCount"`
}

// CategoryCount is a license compliance category with component count.
type CategoryCount struct {
	Category       string
	ComponentCount int64
}

// DailyCount is a day + SBOM ingestion count for the timeline chart.
type DailyCount struct {
	Day   string
	Count int64
}

// PagedResult wraps a paginated result set.
type PagedResult[T any] struct {
	Data   []T   `json:"data"`
	Total  int64 `json:"total"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// ArtifactVersionsPage is a page of artifact versions plus the metadata the
// client needs to drive the Semver/All view toggle.
type ArtifactVersionsPage struct {
	PagedResult[ArtifactVersion]
	// HasSemver reports whether the artifact has any semver-parseable version.
	HasSemver bool
	// ResolvedMode is the concrete sort mode applied ("semver" or "all").
	ResolvedMode VersionSortMode
}

// VulnerabilityDetailResult is everything one advisory page needs: the record
// itself, the two affected-entity pages, and the scope figure that describes
// the whole affected set rather than a page of it. It replaces a four-value
// return, where every error path had to spell out three zero values.
//
// Detail is nil when no vulnerability carries the requested id — the caller
// turns that into a 404, which is why it is not an error here.
type VulnerabilityDetailResult struct {
	Detail     *VulnDetail
	Artifacts  PagedResult[AffectedArtifact]
	Components PagedResult[AffectedComponent]
	// NamespaceCount is how many namespaces visible to the caller hold at
	// least one affected SBOM. "How far has this spread" is the question a
	// reader arrives with, and the artifact page cannot answer it: a page of
	// 25 artifacts says nothing about the namespaces of the other 4,000.
	NamespaceCount int64
}

// ComponentVersionsPage is a page of component occurrences plus the two figures
// that describe the whole result set rather than the window: how many distinct
// versions exist under this identity, and how many artifacts carry it. Both are
// what a summary band is asked for, and neither can be derived from a page —
// which is why the page that has them today declines to state them at all.
type ComponentVersionsPage struct {
	PagedResult[ComponentVersionEntry]
	// VersionCount is the number of distinct versions across every page.
	VersionCount int64
	// ArtifactCount is the number of distinct artifacts whose SBOMs contain
	// this component, across every page.
	ArtifactCount int64
}

// CursorPage wraps a keyset-paginated result set. The caller derives the next
// cursor from the last item; HasMore reports whether further rows exist.
type CursorPage[T any] struct {
	Data    []T
	HasMore bool
}

// SBOMFilter holds parameters for listing SBOMs. Pagination is keyset-based:
// Cursor* point just past the last row of the previous page (ordered by
// created_at DESC, id DESC); HasCursor is false for the first page.
type SBOMFilter struct {
	SerialNumber    string
	Digest          string
	Limit           int32
	CursorCreatedAt time.Time
	CursorID        string
	HasCursor       bool
	Visibility      VisibilityFilter
}

// ComponentFilter holds parameters for searching components.
type ComponentFilter struct {
	Name string
	// Purl matches a component's package URL exactly (ADR-042 R6). It is the
	// only cross-SBOM key a component has, since component rows are
	// SBOM-scoped.
	Purl       string
	Group      string
	Version    string
	Type       string
	PurlType   string
	Sort       string
	SortDir    string
	Limit      int32
	Offset     int32
	Visibility VisibilityFilter
}

// ComponentVersionFilter holds parameters for GetComponentVersions.
//
// Paginated per ADR-043: the ordering is a stable version sort over immutable
// rows, but the UI shows numbered pages with a total, so offset is the derived
// style rather than a keyset cursor.
type ComponentVersionFilter struct {
	Name       string
	Group      string
	Version    string
	Type       string
	Limit      int32
	Offset     int32
	Visibility VisibilityFilter
}

// LicenseFilter holds parameters for listing licenses.
type LicenseFilter struct {
	SpdxID     string
	Name       string
	Category   string
	Limit      int32
	Offset     int32
	Visibility VisibilityFilter
}

// ArtifactFilter holds parameters for listing artifacts. Pagination is
// keyset-based on (name, type, id); Cursor* point just past the last row of the
// previous page and HasCursor is false for the first page.
type ArtifactFilter struct {
	Type              string
	Name              string
	RequireSufficient bool
	Limit             int32
	CursorName        string
	CursorType        string
	CursorID          string
	HasCursor         bool
	Visibility        VisibilityFilter

	// SortSeverity orders by the newest SBOM's severity counts instead of
	// (name, type, id), and with it the pagination style changes: those
	// counts are a rollup a refresh pass rewrites underneath the reader, so
	// ADR-043 rule (1) rules out a keyset cursor and Offset carries the page
	// instead. The caller keeps handing back an opaque cursor either way.
	SortSeverity bool
	SortDesc     bool
	Offset       int32
}

// SBOMByArtifactPage carries keyset pagination state for ListSBOMsByArtifact,
// ordered by (created_at DESC, id DESC).
type SBOMByArtifactPage struct {
	Limit           int32
	CursorCreatedAt time.Time
	CursorID        string
	HasCursor       bool
}

// ComponentPage carries keyset pagination state for ListSBOMComponentsPage,
// ordered by (name, group_name, id).
type ComponentPage struct {
	Limit      int32
	CursorName string
	// CursorGroup is the folded group key (NULL group_name compares as "").
	CursorGroup string
	CursorID    string
	HasCursor   bool
}

// DriftPage carries keyset pagination state for the provenance drift feeds,
// ordered by (detected_at DESC, id DESC).
type DriftPage struct {
	Limit            int32
	CursorDetectedAt time.Time
	CursorID         string
	HasCursor        bool
}

// FeedPage carries keyset pagination state for a self-scoped feed ordered by
// (created_at DESC, id DESC) — the workspace activity stream and the artifact
// watchlist both have exactly this shape (ADR-043 rule 2).
//
// It is one type rather than one per feed on purpose: the handlers that drive
// these feeds share a body (see meCursorList in the API layer), and that
// sharing is only possible while the page parameter is a single type.
type FeedPage struct {
	Limit           int32
	CursorCreatedAt time.Time
	CursorID        string
	HasCursor       bool
}

// ActivityEntry is one event in a user's workspace feed: an SBOM that landed in
// a namespace they own. Source and artifact are optional because an SBOM can
// outlive the source it arrived through, and can be ingested before its
// artifact is resolved.
type ActivityEntry struct {
	SBOMID         string    `json:"sbomId"`
	Digest         *string   `json:"digest,omitempty"`
	SubjectVersion *string   `json:"subjectVersion,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	NamespaceID    string    `json:"namespaceId"`
	NamespaceName  string    `json:"namespaceName"`
	SourceID       *string   `json:"sourceId,omitempty"`
	SourceName     *string   `json:"sourceName,omitempty"`
	SourceKind     *string   `json:"sourceKind,omitempty"`
	ArtifactID     *string   `json:"artifactId,omitempty"`
	ArtifactName   *string   `json:"artifactName,omitempty"`
	ArtifactType   *string   `json:"artifactType,omitempty"`
}

// ArtifactSummary is a lightweight artifact representation for list views.
type ArtifactSummary struct {
	ID                  string  `json:"id"`
	Type                string  `json:"type"`
	Name                string  `json:"name"`
	Group               *string `json:"group,omitempty"`
	SbomCount           int64   `json:"sbomCount"`
	SufficientSbomCount int64   `json:"sufficientSbomCount"`
	SigningStatus       string  `json:"signingStatus"`

	// Vulns is nil when the artifact's newest SBOM has no sbom_vuln_rollup
	// row, which means "no known vulnerabilities" or "never scanned" without
	// distinguishing them. Callers must render nil as unknown, never as a
	// clean zero (ADR-044) — the same contract ArtifactVersion.Vulns carries.
	Vulns *VulnSummary `json:"vulns,omitempty"`
}

// ArtifactDetail extends ArtifactSummary with full metadata.
type ArtifactDetail struct {
	ArtifactSummary
	Purl         *string   `json:"purl,omitempty"`
	Cpe          *string   `json:"cpe,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	VersionCount int64     `json:"versionCount"`
	// Watched reports whether the calling user has this artifact on their
	// watchlist. It rides along with the detail response so the star renders
	// in its final state on first paint rather than flipping in after a
	// second round trip (ocidex-998g.3). It is always false for an
	// unauthenticated caller, who has no watchlist.
	Watched bool `json:"watched"`
}

// ArtifactVersion is a grouped version entry for an artifact.
type ArtifactVersion struct {
	VersionKey    string     `json:"versionKey"`
	SbomID        string     `json:"sbomId"`
	SBOMCount     int64      `json:"sbomCount"`
	Architectures []string   `json:"architectures"`
	ImageVersion  *string    `json:"imageVersion,omitempty"`
	Revision      *string    `json:"revision,omitempty"`
	SourceURL     *string    `json:"sourceUrl,omitempty"`
	BuildDate     *time.Time `json:"buildDate,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	Sufficient    bool       `json:"sufficient"`
	SigningStatus string     `json:"signingStatus"`
	// Vulns is nil when sbom_vuln_rollup has no row for this version's newest
	// SBOM, which means "no known vulnerabilities" or "never scanned" without
	// distinguishing them. Callers must render nil as unknown, never as a clean
	// zero (ADR-044) — the same contract SBOMDetail's tile already follows.
	Vulns *VulnSummary `json:"vulns,omitempty"`
}

// SBOMSummary is a lightweight SBOM representation for list views.
type SBOMSummary struct {
	ID             string     `json:"id"`
	SerialNumber   *string    `json:"serialNumber,omitempty"`
	SpecVersion    string     `json:"specVersion"`
	Version        int32      `json:"version"`
	ArtifactID     *string    `json:"artifactId,omitempty"`
	SubjectVersion *string    `json:"subjectVersion,omitempty"`
	Digest         *string    `json:"digest,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	ComponentCount int64      `json:"componentCount,omitempty"`
	BuildDate      *time.Time `json:"buildDate,omitempty"`
	ImageVersion   *string    `json:"imageVersion,omitempty"`
	Architecture   *string    `json:"architecture,omitempty"`
	Flavor         *string    `json:"flavor,omitempty"`
	Revision       *string    `json:"revision,omitempty"`
	SourceURL      *string    `json:"sourceUrl,omitempty"`
	Sufficient     bool       `json:"sufficient"`
}

// SBOMDetail extends SBOMSummary with optional raw BOM data and enrichments.
type SBOMDetail struct {
	SBOMSummary
	// PackageCount is the number of non-file components (what the packages tab
	// shows); ComponentCount counts all components including files.
	PackageCount int64                      `json:"packageCount"`
	RawBOM       json.RawMessage            `json:"rawBom,omitempty"`
	Enrichments  map[string]json.RawMessage `json:"enrichments,omitempty"`
	// SigningStatus is the terminal signing status derived from this SBOM's
	// provenance enrichment ("unsigned" when none exists).
	SigningStatus string `json:"signingStatus"`
	// VulnSummary is the per-severity count of vulnerability findings across the
	// SBOM's packages, derived by joining component.purl against the vulnerability
	// store. Nil when the SBOM has no known vulnerabilities.
	VulnSummary *VulnSummary `json:"vulnSummary,omitempty"`
	// ProvenanceDrift is the most recent recorded change in this SBOM's signing
	// status (e.g. verified -> verification_failed after a trust config change
	// or registry deletion). Nil when no drift has ever been recorded.
	ProvenanceDrift *ProvenanceDriftSummary `json:"provenanceDrift,omitempty"`
}

// ProvenanceDriftSummary is the most recent provenance_drift_events row for a SBOM.
type ProvenanceDriftSummary struct {
	// ID is the event's primary key. It is the tiebreaker half of the
	// (detected_at, id) keyset cursor, so the drift feeds cannot page without
	// it. Empty for GetLatestProvenanceDrift, which is not paginated.
	ID             string    `json:"id,omitempty"`
	PreviousStatus string    `json:"previousStatus"`
	NewStatus      string    `json:"newStatus"`
	Reason         string    `json:"reason"`
	DetectedAt     time.Time `json:"detectedAt"`
}

// VulnSummary is the per-severity vulnerability finding count for an SBOM. A
// finding is one (package purl, vulnerability) pair.
type VulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// ChangeCounts is a per-direction breakdown of component changes.
type ChangeCounts struct {
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Upgraded   int `json:"upgraded"`
	Downgraded int `json:"downgraded"`
	Modified   int `json:"modified"`
}

// ComponentSummary is a lightweight component representation.
type ComponentSummary struct {
	ID                string        `json:"id"`
	SbomID            string        `json:"sbomId"`
	BomRef            *string       `json:"bomRef,omitempty"`
	Type              string        `json:"type"`
	Name              string        `json:"name"`
	Group             *string       `json:"group,omitempty"`
	Version           *string       `json:"version,omitempty"`
	Purl              *string       `json:"purl,omitempty"`
	IsDirect          bool          `json:"isDirect"`
	DescendantChanges *ChangeCounts `json:"descendantChanges,omitempty"`
	// VulnCount is the number of known vulnerabilities affecting this component's
	// purl; MaxSeverity is the highest severity among them. Both zero-valued when
	// the component has no known vulnerabilities.
	VulnCount     int    `json:"vulnCount,omitempty"`
	MaxSeverity   string `json:"maxSeverity,omitempty"`
	CriticalCount int    `json:"criticalCount,omitempty"`
	HighCount     int    `json:"highCount,omitempty"`
	MediumCount   int    `json:"mediumCount,omitempty"`
	LowCount      int    `json:"lowCount,omitempty"`
	UnknownCount  int    `json:"unknownCount,omitempty"`
}

// ComponentDetail extends ComponentSummary with full metadata.
type ComponentDetail struct {
	ComponentSummary
	BomRef       *string            `json:"bomRef,omitempty"`
	Cpe          *string            `json:"cpe,omitempty"`
	Description  *string            `json:"description,omitempty"`
	Scope        *string            `json:"scope,omitempty"`
	Publisher    *string            `json:"publisher,omitempty"`
	Copyright    *string            `json:"copyright,omitempty"`
	Hashes       []HashEntry        `json:"hashes"`
	Licenses     []LicenseSummary   `json:"licenses"`
	ExternalRefs []ExternalRefEntry `json:"externalReferences"`
	// FoundBy is the syft cataloger that detected this component (e.g.
	// "deb-db-cataloger", "binary-cataloger").
	FoundBy *string `json:"foundBy,omitempty"`
	// Confidence is derived at read time from FoundBy, not stored. Only set
	// to "low" for binary-cataloger detections (no package-manager DB behind
	// them); nil otherwise.
	Confidence *string `json:"confidence,omitempty"`
	// SourcePackage is the name of the source package this component was
	// built from (e.g. a Debian source package), when known.
	SourcePackage *string `json:"sourcePackage,omitempty"`
	// LayerID is the syft-reported content digest of the OCI layer this
	// component was found in (e.g. "sha256:..."), when known.
	LayerID *string `json:"layerId,omitempty"`
	// Layer is LayerID's zero-based position in the image's layer stack,
	// resolved from the oci-metadata enrichment's layer list. Nil when
	// LayerID is unset or the enrichment has no matching layer.
	Layer *int `json:"layer,omitempty"`
	// FromBaseImage is true when Layer is 0 and the image declares a base
	// image. Coarse heuristic — only the bottom-most layer is attributed to
	// the base; multi-layer base images are under-counted. See ADR-0034.
	FromBaseImage bool `json:"fromBaseImage,omitempty"`
}

// HashEntry represents a component hash.
type HashEntry struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// LicenseSummary is a lightweight license representation.
type LicenseSummary struct {
	ID     string  `json:"id"`
	SpdxID *string `json:"spdxId,omitempty"`
	Name   string  `json:"name"`
	URL    *string `json:"url,omitempty"`
}

// ExternalRefEntry represents an external reference.
type ExternalRefEntry struct {
	Type    string  `json:"type"`
	URL     string  `json:"url"`
	Comment *string `json:"comment,omitempty"`
}

// LicenseCount represents a license with its component count and compliance category.
type LicenseCount struct {
	ID             string  `json:"id"`
	SpdxID         *string `json:"spdxId,omitempty"`
	Name           string  `json:"name"`
	URL            *string `json:"url,omitempty"`
	ComponentCount int64   `json:"componentCount"`
	Category       string  `json:"category"`
}

// DistinctComponentSummary represents a unique component (by name+group+type) with counts.
type DistinctComponentSummary struct {
	Name         string   `json:"name"`
	Group        *string  `json:"group,omitempty"`
	Type         string   `json:"type"`
	PurlTypes    []string `json:"purlTypes,omitempty"`
	VersionCount int64    `json:"versionCount"`
	SbomCount    int64    `json:"sbomCount"`
}

// ComponentVersionEntry represents a specific version of a component and the SBOM it came from.
type ComponentVersionEntry struct {
	ID             string  `json:"id"`
	SbomID         string  `json:"sbomId"`
	Type           string  `json:"type"`
	Name           string  `json:"name"`
	Group          *string `json:"group,omitempty"`
	Version        *string `json:"version,omitempty"`
	Purl           *string `json:"purl,omitempty"`
	ArtifactID     *string `json:"artifactId,omitempty"`
	SubjectVersion *string `json:"subjectVersion,omitempty"`
	SbomDigest     *string `json:"sbomDigest,omitempty"`
	ArtifactName   *string `json:"artifactName,omitempty"`
	SbomCreatedAt  string  `json:"sbomCreatedAt"`
	Architecture   *string `json:"architecture,omitempty"`
	VulnCount      int     `json:"vulnCount"`
	MaxSeverity    string  `json:"maxSeverity,omitempty"`
	CriticalCount  int     `json:"criticalCount,omitempty"`
	HighCount      int     `json:"highCount,omitempty"`
	MediumCount    int     `json:"mediumCount,omitempty"`
	LowCount       int     `json:"lowCount,omitempty"`
	UnknownCount   int     `json:"unknownCount,omitempty"`
}

// DependencyGraph represents the dependency structure of an SBOM.
type DependencyGraph struct {
	Nodes []ComponentSummary `json:"nodes"`
	Edges []DependencyEdge   `json:"edges"`
	Roots []string           `json:"roots"`
}

// DiffTree combines a changelog entry with the filtered (non-file) dependency
// graph of the "to" SBOM, allowing clients to render a tree-structured diff
// in a single API call.
type DiffTree struct {
	From    SBOMRef            `json:"from"`
	To      SBOMRef            `json:"to"`
	Summary ChangeSummary      `json:"summary"`
	Changes []ComponentDiff    `json:"changes"`
	Nodes   []ComponentSummary `json:"nodes"`
	Edges   []DependencyEdge   `json:"edges"`
	Roots   []string           `json:"roots"`
}

// DependencyEdge represents a directed dependency relationship.
type DependencyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type searchService struct {
	db            repository.DBTX
	warmDB        repository.DBTX
	statsCache    *ttlCache[DashboardStats]
	discoverCache *ttlCache[Discovery]
}

// warmHandle is the database handle for out-of-band aggregates, falling back to
// the request handle when none was configured (as when the struct is built
// directly rather than through NewSearchService).
func (s *searchService) warmHandle() repository.DBTX {
	if s.warmDB != nil {
		return s.warmDB
	}
	return s.db
}

// SearchOption customizes a SearchService at construction.
type SearchOption func(*searchService)

// WithWarmDB routes the out-of-band dashboard aggregates at a separate database
// handle. Those queries run for minutes; pointing them at a small dedicated
// pool keeps them from occupying connections the request path is waiting on.
// The cache they fill is still the one requests read, so this must be applied
// to the same SearchService the handlers use — not a second instance, which
// would warm a cache nobody reads.
func WithWarmDB(db repository.DBTX) SearchOption {
	return func(s *searchService) {
		if db != nil {
			s.warmDB = db
		}
	}
}

// NewSearchService creates a new SearchService.
func NewSearchService(db repository.DBTX, opts ...SearchOption) SearchService {
	s := &searchService{
		db:            db,
		warmDB:        db,
		statsCache:    newStatsCache(statsCacheTTL),
		discoverCache: newTTLCache[Discovery](statsCacheTTL),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Ensure *Queries satisfies SearchRepository.
var _ repository.SearchRepository = (*repository.Queries)(nil)

// Helper functions for pgtype → Go type conversion.

func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func textToPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func uuidToPtr(u pgtype.UUID) *string {
	if !u.Valid {
		return nil
	}
	s := uuidToString(u)
	return &s
}

// uuidOrNull parses a UUID string into a pgtype.UUID, yielding an invalid
// (NULL) value for an empty or unparseable string.
func uuidOrNull(s string) pgtype.UUID {
	if s == "" {
		return pgtype.UUID{}
	}
	parsed, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}
}

func toComponentSummary(id, sbomID pgtype.UUID, bomRef pgtype.Text, typ, name string, group, version, purl pgtype.Text) ComponentSummary {
	return ComponentSummary{
		ID:      uuidToString(id),
		SbomID:  uuidToString(sbomID),
		BomRef:  textToPtr(bomRef),
		Type:    typ,
		Name:    name,
		Group:   textToPtr(group),
		Version: textToPtr(version),
		Purl:    textToPtr(purl),
	}
}

func interfaceToStringPtr(v interface{}) *string {
	if v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}

func interfaceToTimePtr(v interface{}) *time.Time {
	if v == nil {
		return nil
	}
	t, ok := v.(time.Time)
	if !ok {
		return nil
	}
	return &t
}

func visAdminBool(v VisibilityFilter) pgtype.Bool {
	return pgtype.Bool{Bool: v.IsAdmin, Valid: true}
}

func toLicenseSummary(l repository.License) LicenseSummary {
	return LicenseSummary{
		ID:     uuidToString(l.ID),
		SpdxID: textToPtr(l.SpdxID),
		Name:   l.Name,
		URL:    textToPtr(l.Url),
	}
}
