package service

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Workload match states (ADR-044 K4/K5). These mirror the match_state column
// ListClusterWorkloads projects, and they are exhaustive: every workload is in
// exactly one.
const (
	// MatchExact means the running digest equals sbom.digest — a per-platform
	// match.
	MatchExact = "exact"
	// MatchIndex means the running digest equals sbom.index_digest: the workload
	// runs some platform of a scanned multi-arch image. Which platform is
	// genuinely unknown, because the cluster does not report one.
	MatchIndex = "index"
	// MatchUnknown means a valid digest matching no ingested SBOM — a coverage
	// gap. The remedy is to ingest an SBOM.
	MatchUnknown = "unknown"
	// MatchUnresolvable means no digest could be read from the container's
	// imageID at all — an agent or runtime gap. The remedy is to investigate the
	// node, not to ingest anything.
	MatchUnresolvable = "unresolvable"
)

// Cluster is a registered Kubernetes cluster reporting its running workloads
// (ADR-044). Like Source, it carries no ownership of its own: visibility is
// always resolved through the owning namespace.
type Cluster struct {
	ID            string
	NamespaceID   string
	NamespaceName string // populated by List; empty elsewhere
	Name          string
	Description   string
	LastSeenAt    *time.Time // nil until an agent has reported
	// AutoIngest submits a scan job for every unknown running image whose host
	// resolves to a registry in this cluster's namespace, on every accepted
	// snapshot. On by default: the point of knowing what runs is to scan it.
	AutoIngest bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ClusterWorkload is one running container image in a cluster, as last reported.
type ClusterWorkload struct {
	ID            string
	ClusterID     string
	K8sNamespace  string
	WorkloadKind  string
	WorkloadName  string
	ContainerName string
	ImageRef      string
	ImageDigest   string // empty when the agent could not resolve one
	PodCount      int32
	FirstSeenAt   time.Time
	LastSeenAt    time.Time

	// MatchState is one of the Match* constants. It is never empty: a workload
	// OCIDex could not match reports why, rather than reporting nothing.
	MatchState     string
	SBOMID         string
	ArtifactID     string
	ArtifactName   string
	ArtifactType   string
	SubjectVersion string

	// Vulns is the finding count for the matched SBOM, and is nil for a
	// workload that never matched one. Nil and an all-zero count are different
	// facts — "not assessed" versus "assessed and clean" — and the pointer is
	// what keeps a renderer from printing the first as the second (ADR-044 K5).
	Vulns *VulnCounts
}

// VulnCounts is a per-severity finding count over one SBOM, deduplicated by
// canonical id so an OSV alias group counts once.
type VulnCounts struct {
	Critical int64
	High     int64
	Medium   int64
	Low      int64
}

// Matched reports whether this workload resolved to a known SBOM by either
// join tier.
func (w ClusterWorkload) Matched() bool {
	return w.MatchState == MatchExact || w.MatchState == MatchIndex
}

// WorkloadCoverage is the accounting that must accompany any vulnerability
// figure reported over running workloads (ADR-044 K5). Reporting "3 criticals
// running" without saying how many workloads were not matched at all turns
// missing data into a clean bill of health.
type WorkloadCoverage struct {
	Total        int64
	Matched      int64
	Unknown      int64
	Unresolvable int64
	// Pods is how many running pods those workload-containers add up to. It is
	// reported beside Total, never instead of it: Total is the unit the match
	// states partition, so it stays the denominator.
	Pods int64
}

// RunningVuln is one vulnerability carried by images currently running in a
// cluster.
//
// Rows are keyed by CanonicalID, not by the vulnerability's native id: OSV
// publishes one finding under several ids that alias a single CVE, and a list
// that showed each of them would report one problem three times. ID is the
// representative record the canonical id resolved to, kept so a caller can
// still reach the raw advisory.
type RunningVuln struct {
	ID          string
	CanonicalID string
	Severity    string
	CvssScore   *float32
	Summary     string
	// WorkloadCount counts distinct running workloads across the whole alias
	// group — the number a user can act on, not a count of component rows.
	WorkloadCount int64
}

// WorkloadParams filters and pages ListWorkloads.
//
// The filters deliberately do not reach Coverage: the coverage band stays
// cluster-wide however the table is filtered, because a vulnerability count
// whose denominator moves with the filter is the ambiguity ADR-044 K5 exists to
// prevent.
type WorkloadParams struct {
	K8sNamespace string // empty means every namespace
	MatchState   string // empty means every state
	Query        string // substring over workload, container and image ref
	SortBy       string // one of WorkloadSortKeys; empty means the default
	SortDir      string // "asc" or "desc"; empty means "asc"
	Limit        int32
	Offset       int32
}

// WorkloadSortKeys are the columns ListWorkloads will order by. Anything else
// falls back to the query's default ordering rather than reaching the database:
// the sort key is interpolated into a CASE, so an unrecognised value would
// silently produce an arbitrary order that looks like a working sort.
var WorkloadSortKeys = map[string]bool{
	"k8s_namespace":  true,
	"workload_name":  true,
	"container_name": true,
	"image_ref":      true,
	"match_state":    true,
	"pod_count":      true,
	"last_seen_at":   true,
	"vuln_count":     true,
}

// ClusterImage is one distinct image running in a cluster, with the workloads
// running it collapsed into counts.
//
// It is the same inventory ClusterWorkload describes, keyed by the unit of the
// remedy rather than the unit of the deployment: fourteen replicas of one
// unscanned image are one SBOM to ingest. MatchState and Vulns carry exactly
// the meaning they carry on ClusterWorkload — including Vulns being nil rather
// than zero for an image that was never assessed (ADR-044 K5).
type ClusterImage struct {
	ImageRef    string
	ImageDigest string // empty when the agent could not resolve one

	// WorkloadCount is how many workload-containers run this image; PodCount is
	// how many running pods they add up to. NamespaceCount is how many k8s
	// namespaces it appears in.
	WorkloadCount  int64
	PodCount       int64
	NamespaceCount int64

	// SampleNamespace and SampleWorkload name one place the image runs, chosen
	// deterministically. They are an example, not the whole answer: the
	// by-workload view lists every one.
	SampleNamespace string
	SampleWorkload  string

	LastSeenAt time.Time

	MatchState     string
	SBOMID         string
	ArtifactID     string
	ArtifactName   string
	ArtifactType   string
	SubjectVersion string

	Vulns *VulnCounts
}

// Matched reports whether this image resolved to a known SBOM by either join
// tier.
func (i ClusterImage) Matched() bool {
	return i.MatchState == MatchExact || i.MatchState == MatchIndex
}

// ImageParams filters and pages the by-image inventory. The filters are the
// same ones WorkloadParams carries, so switching the grouping in the UI keeps
// whatever the reader had narrowed to.
type ImageParams struct {
	K8sNamespace string
	MatchState   string
	Query        string
	SortBy       string // one of ImageSortKeys; empty means the default
	SortDir      string // "asc" or "desc"; empty means "asc"
	Limit        int32
	Offset       int32
}

// ImageSortKeys are the columns ListImages will order by. Same contract as
// WorkloadSortKeys: an unrecognised key is dropped before it reaches the CASE
// it would be interpolated into.
var ImageSortKeys = map[string]bool{
	"image_ref":      true,
	"match_state":    true,
	"workload_count": true,
	"pod_count":      true,
	"last_seen_at":   true,
	"vuln_count":     true,
}

// NamespaceFacet is one k8s namespace present in a cluster and how many
// containers it accounts for. It is computed server-side because the workload
// list is paginated: a filter built from the current page would silently hide
// every other namespace in the cluster.
type NamespaceFacet struct {
	K8sNamespace  string
	WorkloadCount int64
}

// RunningVulnParams filters and pages ListRunningVulns.
type RunningVulnParams struct {
	Severity string // empty means every severity
	SortBy   string // one of RunningVulnSortKeys; empty means the default
	SortDir  string // "asc" or "desc"; empty means "asc"
	Limit    int32
	Offset   int32
}

// RunningVulnSortKeys are the columns RunningVulns will order by. As with
// WorkloadSortKeys, anything else is dropped before it reaches the query's
// CASE, where an unmatched key would produce an arbitrary order that looks
// like a working sort.
var RunningVulnSortKeys = map[string]bool{
	sortBySeverity:    true,
	sortByCVSS:        true,
	"workload_count":  true,
	sortByCanonicalID: true,
}

// RunningWorkload is a workload that carries a given vulnerability, together
// with the cluster it runs in. It is the reverse of RunningVuln: "which
// Deployments are running this CVE".
type RunningWorkload struct {
	ClusterWorkload
	ClusterName string
}

// ReportedWorkload is one entry of an inventory snapshot pushed by an agent.
type ReportedWorkload struct {
	K8sNamespace  string
	WorkloadKind  string
	WorkloadName  string
	ContainerName string
	ImageRef      string
	ImageDigest   string // empty means unresolvable
	PodCount      int32
}

// CreateClusterParams holds the parameters for registering a cluster.
type CreateClusterParams struct {
	NamespaceID string
	Name        string
	Description string
}

// UpdateClusterParams holds the parameters for renaming or re-describing a
// cluster. NamespaceID is deliberately immutable: moving a cluster between
// namespaces would silently change who can see every workload it has reported.
type UpdateClusterParams struct {
	ID          string
	Name        string
	Description string
	// AutoIngest is a pointer so an omitted field leaves the setting alone. A
	// rename must not be able to switch ingest off as a side effect.
	AutoIngest *bool
}

// ClusterService manages registered clusters and the inventory they report.
type ClusterService interface {
	Create(ctx context.Context, params CreateClusterParams) (Cluster, error)
	Get(ctx context.Context, id string) (Cluster, error)
	GetByName(ctx context.Context, namespaceID, name string) (Cluster, error)
	ListByNamespace(ctx context.Context, namespaceID string) ([]Cluster, error)
	List(ctx context.Context, filter VisibilityFilter) ([]Cluster, error)
	Update(ctx context.Context, params UpdateClusterParams) (Cluster, error)
	Delete(ctx context.Context, id string) error

	// ReplaceInventory applies a full snapshot: upsert everything reported,
	// prune everything not reported, stamp last_seen_at. All in one transaction
	// (ADR-044 K7).
	ReplaceInventory(ctx context.Context, clusterID string, workloads []ReportedWorkload) (int, error)

	ListWorkloads(ctx context.Context, clusterID string, params WorkloadParams, filter VisibilityFilter) (PagedResult[ClusterWorkload], error)

	// ListImages is the same inventory grouped by image rather than by
	// workload-container.
	ListImages(ctx context.Context, clusterID string, params ImageParams, filter VisibilityFilter) (PagedResult[ClusterImage], error)

	// NamespaceFacets enumerates the k8s namespaces the filter above can select.
	NamespaceFacets(ctx context.Context, clusterID string, filter VisibilityFilter) ([]NamespaceFacet, error)
	Coverage(ctx context.Context, clusterID string, filter VisibilityFilter) (WorkloadCoverage, error)

	// RunningVulns lists vulnerabilities carried by images running in the
	// cluster. Its result is only meaningful beside Coverage: the findings
	// cover the matched workloads and say nothing at all about the rest
	// (ADR-044 K5).
	RunningVulns(ctx context.Context, clusterID string, params RunningVulnParams, filter VisibilityFilter) (PagedResult[RunningVuln], error)

	// WorkloadsForVulnerability answers the reverse question. clusterID may be
	// empty, which widens it from one cluster's drill-down to "everywhere the
	// caller can see".
	WorkloadsForVulnerability(ctx context.Context, canonicalID, clusterID string, limit int32, filter VisibilityFilter) ([]RunningWorkload, error)

	// UnknownImages lists the cluster's No-SBOM gap grouped by image, each
	// resolved against the registries of the cluster's own namespace.
	UnknownImages(ctx context.Context, clusterID string, limit, offset int32, filter VisibilityFilter) (UnknownImagesPage, error)

	// IngestUnknown submits a scan job for every unknown running image that
	// resolves to a usable registry, and reports what it skipped and why. The
	// skips are returned rather than logged away: "nothing was queued" and
	// "nothing could be queued because no registry serves ghcr.io" look
	// identical from a count alone.
	IngestUnknown(ctx context.Context, clusterID string, sub RunningImageSubmitter, params IngestUnknownParams, filter VisibilityFilter) (IngestResult, error)
}

type clusterService struct {
	pool *pgxpool.Pool
	repo repository.ClusterRepository
}

// NewClusterService constructs a ClusterService. It keeps the pool as well as
// the repository because ReplaceInventory needs to open its own transaction.
func NewClusterService(pool *pgxpool.Pool) ClusterService {
	return &clusterService{pool: pool, repo: repository.New(pool)}
}

func (s *clusterService) Create(ctx context.Context, params CreateClusterParams) (Cluster, error) {
	nsID, err := parseUUID(params.NamespaceID)
	if err != nil {
		return Cluster{}, ErrNotFound
	}
	row, err := s.repo.CreateCluster(ctx, repository.CreateClusterParams{
		NamespaceID: nsID,
		Name:        params.Name,
		Description: params.Description,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Cluster{}, ErrConflict
		}
		return Cluster{}, fmt.Errorf("creating cluster: %w", err)
	}
	return clusterFromRepo(row), nil
}

func (s *clusterService) Get(ctx context.Context, id string) (Cluster, error) {
	cid, err := parseUUID(id)
	if err != nil {
		return Cluster{}, ErrNotFound
	}
	row, err := s.repo.GetCluster(ctx, cid)
	if err != nil {
		return Cluster{}, ErrNotFound
	}
	return clusterFromRepo(row), nil
}

func (s *clusterService) GetByName(ctx context.Context, namespaceID, name string) (Cluster, error) {
	nsID, err := parseUUID(namespaceID)
	if err != nil {
		return Cluster{}, ErrNotFound
	}
	row, err := s.repo.GetClusterByName(ctx, repository.GetClusterByNameParams{
		NamespaceID: nsID,
		Name:        name,
	})
	if err != nil {
		return Cluster{}, ErrNotFound
	}
	return clusterFromRepo(row), nil
}

func (s *clusterService) ListByNamespace(ctx context.Context, namespaceID string) ([]Cluster, error) {
	nsID, err := parseUUID(namespaceID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.repo.ListClustersByNamespace(ctx, nsID)
	if err != nil {
		return nil, fmt.Errorf("listing clusters: %w", err)
	}
	out := make([]Cluster, len(rows))
	for i, row := range rows {
		out[i] = clusterFromRepo(row)
	}
	return out, nil
}

func (s *clusterService) List(ctx context.Context, filter VisibilityFilter) ([]Cluster, error) {
	rows, err := s.repo.ListClusters(ctx, repository.ListClustersParams{
		IsAdmin:   filter.adminFlag(),
		UserID:    filter.UserID,
		OwnedOnly: filter.ownedFlag(),
	})
	if err != nil {
		return nil, fmt.Errorf("listing clusters: %w", err)
	}
	out := make([]Cluster, len(rows))
	for i, r := range rows {
		c := clusterFromRepo(r.Cluster)
		c.NamespaceName = r.NamespaceName
		out[i] = c
	}
	return out, nil
}

func (s *clusterService) Update(ctx context.Context, params UpdateClusterParams) (Cluster, error) {
	cid, err := parseUUID(params.ID)
	if err != nil {
		return Cluster{}, ErrNotFound
	}
	auto := pgtype.Bool{}
	if params.AutoIngest != nil {
		auto = pgtype.Bool{Bool: *params.AutoIngest, Valid: true}
	}
	row, err := s.repo.UpdateCluster(ctx, repository.UpdateClusterParams{
		ID:          cid,
		Name:        params.Name,
		Description: params.Description,
		AutoIngest:  auto,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Cluster{}, ErrConflict
		}
		return Cluster{}, fmt.Errorf("updating cluster: %w", err)
	}
	return clusterFromRepo(row), nil
}

func (s *clusterService) Delete(ctx context.Context, id string) error {
	cid, err := parseUUID(id)
	if err != nil {
		return ErrNotFound
	}
	n, err := s.repo.DeleteCluster(ctx, cid)
	if err != nil {
		return fmt.Errorf("deleting cluster: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReplaceInventory applies a snapshot as a full replacement and returns the
// number of workload rows pruned.
//
// Every row in the snapshot is stamped with one observedAt, and the prune then
// deletes anything for the cluster older than it. That is what makes the
// operation self-healing rather than merely idempotent: a snapshot that a
// previous push missed entirely still leaves the table exactly right, because
// correctness depends only on the latest snapshot and never on the sequence of
// them.
//
// The whole thing is one transaction, so a partially-applied snapshot is never
// visible. A reader mid-push must not see a cluster that appears to be running
// half of what it runs.
func (s *clusterService) ReplaceInventory(ctx context.Context, clusterID string, workloads []ReportedWorkload) (int, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return 0, ErrNotFound
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on a committed tx is a no-op

	q := repository.New(tx)

	// Read inside the transaction so a cluster deleted concurrently cannot have
	// an inventory written against it.
	if _, err := q.GetCluster(ctx, cid); err != nil {
		if err == pgx.ErrNoRows {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("loading cluster: %w", err)
	}

	observed := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}

	for _, w := range workloads {
		var dgst pgtype.Text
		if w.ImageDigest != "" {
			dgst = pgtype.Text{String: w.ImageDigest, Valid: true}
		}
		if err := q.UpsertClusterWorkload(ctx, repository.UpsertClusterWorkloadParams{
			ClusterID:     cid,
			K8sNamespace:  w.K8sNamespace,
			WorkloadKind:  w.WorkloadKind,
			WorkloadName:  w.WorkloadName,
			ContainerName: w.ContainerName,
			ImageRef:      w.ImageRef,
			ImageDigest:   dgst,
			PodCount:      w.PodCount,
			ObservedAt:    observed,
		}); err != nil {
			return 0, fmt.Errorf("upserting workload %s/%s: %w", w.K8sNamespace, w.WorkloadName, err)
		}
	}

	pruned, err := q.PruneClusterWorkloads(ctx, repository.PruneClusterWorkloadsParams{
		ClusterID:  cid,
		ObservedAt: observed,
	})
	if err != nil {
		return 0, fmt.Errorf("pruning workloads: %w", err)
	}

	// last_seen_at is stamped even for an empty snapshot. That is the point of
	// K2: a cluster legitimately running nothing must be distinguishable from a
	// cluster whose agent has died, and only this timestamp can tell them apart.
	if err := q.TouchClusterLastSeen(ctx, repository.TouchClusterLastSeenParams{
		ID:         cid,
		LastSeenAt: observed,
	}); err != nil {
		return 0, fmt.Errorf("stamping last_seen_at: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing inventory: %w", err)
	}
	return int(pruned), nil
}

//nolint:dupl // The by-image listing has the same shape; see ListImages.
func (s *clusterService) ListWorkloads(ctx context.Context, clusterID string, params WorkloadParams, filter VisibilityFilter) (PagedResult[ClusterWorkload], error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return PagedResult[ClusterWorkload]{}, ErrNotFound
	}
	sortBy, sortDir := clampSort(params.SortBy, params.SortDir, WorkloadSortKeys)
	return pagedInventory("workloads", params.Limit, params.Offset,
		func() (int64, error) {
			return s.repo.CountClusterWorkloads(ctx, repository.CountClusterWorkloadsParams{
				ClusterID:    cid,
				K8sNamespace: optionalText(params.K8sNamespace),
				MatchState:   optionalText(params.MatchState),
				Q:            optionalText(params.Query),
				UserID:       filter.UserID,
				IsAdmin:      filter.adminFlag(),
			})
		},
		func(limit, offset int32) ([]repository.ListClusterWorkloadsRow, error) {
			return s.repo.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
				ClusterID:    cid,
				K8sNamespace: optionalText(params.K8sNamespace),
				MatchState:   optionalText(params.MatchState),
				Q:            optionalText(params.Query),
				SortBy:       sortBy,
				SortDir:      sortDir,
				Limit:        pgtype.Int4{Int32: limit, Valid: true},
				Offset:       pgtype.Int4{Int32: offset, Valid: true},
				UserID:       filter.UserID,
				IsAdmin:      filter.adminFlag(),
			})
		}, workloadFromRepo)
}

// ListImages is deliberately the same shape as ListWorkloads. Everything that
// can be shared already is (pagedInventory); what is left is filling in two
// sqlc-generated param structs, which are distinct types with no common
// interface, so the remaining repetition cannot be factored out without
// hand-writing a mapping layer over generated code.
//
//nolint:dupl // see above: the duplicated part is sqlc param assignment.
func (s *clusterService) ListImages(ctx context.Context, clusterID string, params ImageParams, filter VisibilityFilter) (PagedResult[ClusterImage], error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return PagedResult[ClusterImage]{}, ErrNotFound
	}
	sortBy, sortDir := clampSort(params.SortBy, params.SortDir, ImageSortKeys)
	return pagedInventory("images", params.Limit, params.Offset,
		func() (int64, error) {
			return s.repo.CountClusterImages(ctx, repository.CountClusterImagesParams{
				ClusterID:    cid,
				K8sNamespace: optionalText(params.K8sNamespace),
				MatchState:   optionalText(params.MatchState),
				Q:            optionalText(params.Query),
				UserID:       filter.UserID,
				IsAdmin:      filter.adminFlag(),
			})
		},
		func(limit, offset int32) ([]repository.ListClusterImagesRow, error) {
			return s.repo.ListClusterImages(ctx, repository.ListClusterImagesParams{
				ClusterID:    cid,
				K8sNamespace: optionalText(params.K8sNamespace),
				MatchState:   optionalText(params.MatchState),
				Q:            optionalText(params.Query),
				SortBy:       sortBy,
				SortDir:      sortDir,
				Limit:        pgtype.Int4{Int32: limit, Valid: true},
				Offset:       pgtype.Int4{Int32: offset, Valid: true},
				UserID:       filter.UserID,
				IsAdmin:      filter.adminFlag(),
			})
		}, imageFromRepo)
}

// pagedInventory is the count-then-page-then-project sequence the two inventory
// listings share.
//
// The count is a separate query rather than len(rows) because the list is
// paginated: a total taken from the page would report a 50-row page of a
// 300-image cluster as 50, which is the same class of quiet undercount the
// coverage figures exist to prevent.
func pagedInventory[Row, Out any](
	what string,
	reqLimit, reqOffset int32,
	count func() (int64, error),
	list func(limit, offset int32) ([]Row, error),
	project func(Row) Out,
) (PagedResult[Out], error) {
	limit, offset := clampPage(reqLimit, reqOffset)
	total, err := count()
	if err != nil {
		return PagedResult[Out]{}, fmt.Errorf("counting %s: %w", what, err)
	}
	rows, err := list(limit, offset)
	if err != nil {
		return PagedResult[Out]{}, fmt.Errorf("listing %s: %w", what, err)
	}
	out := make([]Out, len(rows))
	for i, r := range rows {
		out[i] = project(r)
	}
	return PagedResult[Out]{Data: out, Total: total, Limit: limit, Offset: offset}, nil
}

// NamespaceFacets lists every k8s namespace the cluster reports, with its
// container count, so the workload filter offers the whole cluster rather than
// whichever namespaces happen to be on the current page.
func (s *clusterService) NamespaceFacets(ctx context.Context, clusterID string, filter VisibilityFilter) ([]NamespaceFacet, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.repo.ListClusterK8sNamespaces(ctx, repository.ListClusterK8sNamespacesParams{
		ClusterID: cid,
		UserID:    filter.UserID,
		IsAdmin:   filter.adminFlag(),
	})
	if err != nil {
		return nil, fmt.Errorf("listing cluster namespaces: %w", err)
	}
	out := make([]NamespaceFacet, len(rows))
	for i, r := range rows {
		out[i] = NamespaceFacet{K8sNamespace: r.K8sNamespace, WorkloadCount: r.WorkloadCount}
	}
	return out, nil
}

func (s *clusterService) Coverage(ctx context.Context, clusterID string, filter VisibilityFilter) (WorkloadCoverage, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return WorkloadCoverage{}, ErrNotFound
	}
	row, err := s.repo.GetClusterWorkloadCoverage(ctx, repository.GetClusterWorkloadCoverageParams{
		ClusterID: cid,
		UserID:    filter.UserID,
		IsAdmin:   filter.adminFlag(),
	})
	if err != nil {
		return WorkloadCoverage{}, fmt.Errorf("computing coverage: %w", err)
	}
	return WorkloadCoverage{
		Total:        row.Total,
		Matched:      row.Matched,
		Unknown:      row.Unknown,
		Unresolvable: row.Unresolvable,
		Pods:         row.Pods,
	}, nil
}

// RunningVulns lists the cluster's running vulnerabilities, most severe first.
func (s *clusterService) RunningVulns(ctx context.Context, clusterID string, params RunningVulnParams, filter VisibilityFilter) (PagedResult[RunningVuln], error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return PagedResult[RunningVuln]{}, ErrNotFound
	}
	limit, offset := clampPage(params.Limit, params.Offset)

	severity := optionalText(params.Severity)

	total, err := s.repo.CountClusterRunningVulns(ctx, repository.CountClusterRunningVulnsParams{
		ClusterID: cid,
		Severity:  severity,
		UserID:    filter.UserID,
		IsAdmin:   filter.adminFlag(),
	})
	if err != nil {
		return PagedResult[RunningVuln]{}, fmt.Errorf("counting running vulnerabilities: %w", err)
	}

	sortBy, sortDir := clampSort(params.SortBy, params.SortDir, RunningVulnSortKeys)
	rows, err := s.repo.ListClusterRunningVulns(ctx, repository.ListClusterRunningVulnsParams{
		ClusterID: cid,
		Severity:  severity,
		SortBy:    sortBy,
		SortDir:   sortDir,
		Limit:     pgtype.Int4{Int32: limit, Valid: true},
		Offset:    pgtype.Int4{Int32: offset, Valid: true},
		UserID:    filter.UserID,
		IsAdmin:   filter.adminFlag(),
	})
	if err != nil {
		return PagedResult[RunningVuln]{}, fmt.Errorf("listing running vulnerabilities: %w", err)
	}

	data := make([]RunningVuln, len(rows))
	for i, r := range rows {
		v := RunningVuln{
			ID:            r.ID,
			CanonicalID:   r.CanonicalID,
			Severity:      r.Severity.String,
			Summary:       r.Summary.String,
			WorkloadCount: r.WorkloadCount,
		}
		if r.CvssScore.Valid {
			score := r.CvssScore.Float32
			v.CvssScore = &score
		}
		data[i] = v
	}
	return PagedResult[RunningVuln]{Data: data, Total: total, Limit: limit, Offset: offset}, nil
}

// WorkloadsForVulnerability lists the running workloads carrying a canonical
// vulnerability id, optionally narrowed to one cluster.
func (s *clusterService) WorkloadsForVulnerability(ctx context.Context, canonicalID, clusterID string, limit int32, filter VisibilityFilter) ([]RunningWorkload, error) {
	if canonicalID == "" {
		return nil, ErrNotFound
	}
	params := repository.ListWorkloadsForVulnerabilityParams{
		CanonicalID: canonicalID,
		UserID:      filter.UserID,
		IsAdmin:     filter.adminFlag(),
	}
	// An unparseable cluster id is not silently widened to every cluster: that
	// would answer a different, larger question than the caller asked.
	if clusterID != "" {
		cid, err := parseUUID(clusterID)
		if err != nil {
			return nil, ErrNotFound
		}
		params.ClusterID = cid
	}
	lim, _ := clampPage(limit, 0)
	params.Limit = pgtype.Int4{Int32: lim, Valid: true}

	rows, err := s.repo.ListWorkloadsForVulnerability(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("listing workloads for vulnerability: %w", err)
	}
	out := make([]RunningWorkload, len(rows))
	for i, r := range rows {
		out[i] = RunningWorkload{
			ClusterWorkload: workloadFromRepo(repository.ListClusterWorkloadsRow{
				ClusterWorkload: r.ClusterWorkload,
				SbomID:          r.SbomID,
				ArtifactID:      r.ArtifactID,
				SubjectVersion:  r.SubjectVersion,
				ArtifactName:    r.ArtifactName,
				MatchState:      r.MatchState,
			}),
			ClusterName: r.ClusterName,
		}
	}
	return out, nil
}

// optionalText maps an empty filter value to SQL NULL, which every filter in
// db/queries/cluster.sql reads as "no filter".
func optionalText(v string) pgtype.Text {
	if v == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: v, Valid: true}
}

// clampPage applies the same bounds huma declares on PaginationParams, so a
// caller that bypasses the HTTP layer (a test, the MCP server) cannot ask for
// an unbounded page.
// clampSort reduces a caller's sort request to a pair the query understands. An
// unknown key becomes the empty string, which matches no CASE branch and so
// leaves the query's default ordering in place.
func clampSort(sortBy, sortDir string, allowed map[string]bool) (string, string) {
	if !allowed[sortBy] {
		sortBy = ""
	}
	if sortDir != "desc" {
		sortDir = "asc"
	}
	return sortBy, sortDir
}

func clampPage(limit, offset int32) (int32, int32) {
	switch {
	case limit <= 0:
		limit = 20
	case limit > 200:
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func clusterFromRepo(c repository.Cluster) Cluster {
	out := Cluster{
		ID:          uuidToStr(c.ID),
		NamespaceID: uuidToStr(c.NamespaceID),
		Name:        c.Name,
		Description: c.Description,
		AutoIngest:  c.AutoIngest,
	}
	if c.LastSeenAt.Valid {
		t := c.LastSeenAt.Time
		out.LastSeenAt = &t
	}
	if c.CreatedAt.Valid {
		out.CreatedAt = c.CreatedAt.Time
	}
	if c.UpdatedAt.Valid {
		out.UpdatedAt = c.UpdatedAt.Time
	}
	return out
}

func workloadFromRepo(r repository.ListClusterWorkloadsRow) ClusterWorkload {
	w := r.ClusterWorkload
	out := ClusterWorkload{
		ID:             uuidToStr(w.ID),
		ClusterID:      uuidToStr(w.ClusterID),
		K8sNamespace:   w.K8sNamespace,
		WorkloadKind:   w.WorkloadKind,
		WorkloadName:   w.WorkloadName,
		ContainerName:  w.ContainerName,
		ImageRef:       w.ImageRef,
		ImageDigest:    w.ImageDigest.String,
		PodCount:       w.PodCount,
		MatchState:     r.MatchState,
		SBOMID:         uuidToStr(r.SbomID),
		ArtifactID:     uuidToStr(r.ArtifactID),
		ArtifactName:   r.ArtifactName.String,
		ArtifactType:   r.ArtifactType.String,
		SubjectVersion: r.SubjectVersion.String,
	}
	if w.FirstSeenAt.Valid {
		out.FirstSeenAt = w.FirstSeenAt.Time
	}
	if w.LastSeenAt.Valid {
		out.LastSeenAt = w.LastSeenAt.Time
	}
	// The query coalesces the counts to zero because a lateral aggregate's NULL
	// is not something sqlc can type. Zero from an unmatched row is an artefact
	// of that, not a finding of none, so it is dropped here rather than handed
	// on as a clean bill of health.
	if out.Matched() {
		out.Vulns = &VulnCounts{
			Critical: r.CriticalCount,
			High:     r.HighCount,
			Medium:   r.MediumCount,
			Low:      r.LowCount,
		}
	}
	return out
}

func imageFromRepo(r repository.ListClusterImagesRow) ClusterImage {
	out := ClusterImage{
		ImageRef:        r.ImageRef,
		ImageDigest:     r.ImageDigest.String,
		WorkloadCount:   r.WorkloadCount,
		PodCount:        r.PodCount,
		NamespaceCount:  r.NamespaceCount,
		SampleNamespace: r.SampleNamespace,
		SampleWorkload:  r.SampleWorkload,
		MatchState:      r.MatchState,
		SBOMID:          uuidToStr(r.SbomID),
		ArtifactID:      uuidToStr(r.ArtifactID),
		ArtifactName:    r.ArtifactName.String,
		ArtifactType:    r.ArtifactType.String,
		SubjectVersion:  r.SubjectVersion.String,
	}
	if r.LastSeenAt.Valid {
		out.LastSeenAt = r.LastSeenAt.Time
	}
	// Same reasoning as workloadFromRepo: the query's COALESCE to zero is a
	// typing artefact, and handing it on for an image that was never assessed
	// would report "no findings" where the truth is "no SBOM".
	if out.Matched() {
		out.Vulns = &VulnCounts{
			Critical: r.CriticalCount,
			High:     r.HighCount,
			Medium:   r.MediumCount,
			Low:      r.LowCount,
		}
	}
	return out
}
