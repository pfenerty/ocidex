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
	CreatedAt     time.Time
	UpdatedAt     time.Time
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

	ListWorkloads(ctx context.Context, clusterID string, filter VisibilityFilter) ([]ClusterWorkload, error)
	Coverage(ctx context.Context, clusterID string, filter VisibilityFilter) (WorkloadCoverage, error)
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
	row, err := s.repo.UpdateCluster(ctx, repository.UpdateClusterParams{
		ID:          cid,
		Name:        params.Name,
		Description: params.Description,
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

func (s *clusterService) ListWorkloads(ctx context.Context, clusterID string, filter VisibilityFilter) ([]ClusterWorkload, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.repo.ListClusterWorkloads(ctx, repository.ListClusterWorkloadsParams{
		ClusterID: cid,
		UserID:    filter.UserID,
		IsAdmin:   filter.adminFlag(),
	})
	if err != nil {
		return nil, fmt.Errorf("listing workloads: %w", err)
	}
	out := make([]ClusterWorkload, len(rows))
	for i, r := range rows {
		out[i] = workloadFromRepo(r)
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
	}, nil
}

func clusterFromRepo(c repository.Cluster) Cluster {
	out := Cluster{
		ID:          uuidToStr(c.ID),
		NamespaceID: uuidToStr(c.NamespaceID),
		Name:        c.Name,
		Description: c.Description,
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
	return out
}
