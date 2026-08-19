package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/service"
)

// ListClusters returns the clusters visible to the caller, optionally scoped to
// one namespace. Like sources, visibility is resolved entirely through the
// owning namespace (ADR-039, ADR-044 K6).
func (h *Handler) ListClusters(ctx context.Context, in *ListClustersInput) (*ListClustersOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}

	if in.NamespaceID != "" {
		ns, err := h.namespaceService.Get(ctx, in.NamespaceID)
		if err != nil {
			return nil, huma.Error404NotFound("namespace not found")
		}
		if !canManageNamespace(user, ns) && ns.Visibility == visibilityPrivate {
			return nil, huma.Error404NotFound("namespace not found")
		}
		rows, err := h.clusterService.ListByNamespace(ctx, in.NamespaceID)
		if err != nil {
			return nil, mapServiceError(err)
		}
		out := &ListClustersOutput{}
		out.Body.Data = make([]ClusterResponse, len(rows))
		for i, c := range rows {
			c.NamespaceName = ns.Name
			out.Body.Data[i] = toClusterResponse(c)
		}
		return out, nil
	}

	return h.listClusters(ctx, visibilityFilterFromContext(ctx))
}

// ListMyClusters returns only the clusters in namespaces the caller owns.
func (h *Handler) ListMyClusters(ctx context.Context, _ *ListMyClustersInput) (*ListClustersOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	return h.listClusters(ctx, ownedFilterFromContext(ctx))
}

func (h *Handler) listClusters(ctx context.Context, vis service.VisibilityFilter) (*ListClustersOutput, error) {
	rows, err := h.clusterService.List(ctx, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListClustersOutput{}
	out.Body.Data = make([]ClusterResponse, len(rows))
	for i, c := range rows {
		out.Body.Data[i] = toClusterResponse(c)
	}
	return out, nil
}

// GetCluster returns one cluster, gated on its namespace's visibility.
func (h *Handler) GetCluster(ctx context.Context, in *GetClusterInput) (*GetClusterOutput, error) {
	cluster, err := h.visibleCluster(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	return &GetClusterOutput{Body: toClusterResponse(cluster)}, nil
}

// CreateCluster registers a cluster in a namespace the caller owns.
func (h *Handler) CreateCluster(ctx context.Context, in *CreateClusterInput) (*CreateClusterOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if err := h.namespaceOwnerCheck(ctx, user, in.Body.NamespaceID); err != nil {
		return nil, err
	}
	cluster, err := h.clusterService.Create(ctx, service.CreateClusterParams{
		NamespaceID: in.Body.NamespaceID,
		Name:        in.Body.Name,
		Description: in.Body.Description,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &CreateClusterOutput{Body: toClusterResponse(cluster)}, nil
}

// UpdateCluster renames or re-describes a cluster.
func (h *Handler) UpdateCluster(ctx context.Context, in *UpdateClusterInput) (*UpdateClusterOutput, error) {
	if err := h.clusterOwnerCheck(ctx, in.ID); err != nil {
		return nil, err
	}
	cluster, err := h.clusterService.Update(ctx, service.UpdateClusterParams{
		ID:          in.ID,
		Name:        in.Body.Name,
		Description: in.Body.Description,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &UpdateClusterOutput{Body: toClusterResponse(cluster)}, nil
}

// DeleteCluster removes a cluster and its reported inventory. The SBOMs its
// workloads matched are untouched — inventory is derived state about a cluster,
// not about the catalogue.
func (h *Handler) DeleteCluster(ctx context.Context, in *DeleteClusterInput) (*struct{}, error) {
	if err := h.clusterOwnerCheck(ctx, in.ID); err != nil {
		return nil, err
	}
	if err := h.clusterService.Delete(ctx, in.ID); err != nil {
		return nil, mapServiceError(err)
	}
	return nil, nil
}

// PutInventory replaces a cluster's workload set with the pushed snapshot.
//
// Ownership, not mere visibility, is required: a public namespace makes a
// cluster's inventory readable by anyone, and it must not thereby make it
// writable by anyone.
func (h *Handler) PutInventory(ctx context.Context, in *PutInventoryInput) (*PutInventoryOutput, error) {
	if err := h.clusterOwnerCheck(ctx, in.ID); err != nil {
		return nil, err
	}

	workloads := make([]service.ReportedWorkload, len(in.Body.Workloads))
	for i, w := range in.Body.Workloads {
		workloads[i] = service.ReportedWorkload{
			K8sNamespace:  w.K8sNamespace,
			WorkloadKind:  w.WorkloadKind,
			WorkloadName:  w.WorkloadName,
			ContainerName: w.ContainerName,
			ImageRef:      w.ImageRef,
			ImageDigest:   w.ImageDigest,
			PodCount:      w.PodCount,
		}
	}

	pruned, err := h.clusterService.ReplaceInventory(ctx, in.ID, workloads)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &PutInventoryOutput{}
	out.Body.Accepted = len(workloads)
	out.Body.Pruned = pruned
	out.Body.SeenAt = time.Now().UTC().Format(time.RFC3339)
	return out, nil
}

// ListClusterWorkloads returns what a cluster is running, each row joined to
// the SBOM its digest matches, together with the coverage counts.
func (h *Handler) ListClusterWorkloads(ctx context.Context, in *ListClusterWorkloadsInput) (*ListClusterWorkloadsOutput, error) {
	if _, err := h.visibleCluster(ctx, in.ID); err != nil {
		return nil, err
	}

	vis := visibilityFilterFromContext(ctx)
	result, err := h.clusterService.ListWorkloads(ctx, in.ID, service.WorkloadParams{
		K8sNamespace: in.K8sNamespace,
		MatchState:   in.MatchState,
		Query:        in.Q,
		SortBy:       in.Sort,
		SortDir:      in.Dir,
		Limit:        in.Limit,
		Offset:       in.Offset,
	}, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}
	coverage, err := h.clusterService.Coverage(ctx, in.ID, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListClusterWorkloadsOutput{}
	out.Body.Data = make([]ClusterWorkloadResponse, len(result.Data))
	for i, w := range result.Data {
		out.Body.Data[i] = toWorkloadResponse(w)
	}
	out.Body.Pagination = paginationMeta(result)
	out.Body.Coverage = WorkloadCoverageResponse{
		Total:        coverage.Total,
		Matched:      coverage.Matched,
		Unknown:      coverage.Unknown,
		Unresolvable: coverage.Unresolvable,
	}
	return out, nil
}

// ListClusterNamespaces returns the k8s namespaces the cluster reports, for the
// workload filter's select.
func (h *Handler) ListClusterNamespaces(ctx context.Context, in *ListClusterNamespacesInput) (*ListClusterNamespacesOutput, error) {
	if _, err := h.visibleCluster(ctx, in.ID); err != nil {
		return nil, err
	}
	facets, err := h.clusterService.NamespaceFacets(ctx, in.ID, visibilityFilterFromContext(ctx))
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListClusterNamespacesOutput{}
	out.Body.Data = make([]NamespaceFacetResponse, len(facets))
	for i, f := range facets {
		out.Body.Data[i] = NamespaceFacetResponse{K8sNamespace: f.K8sNamespace, WorkloadCount: f.WorkloadCount}
	}
	return out, nil
}

// ListClusterVulns handles GET /api/v1/clusters/{id}/vulns: the
// vulnerabilities carried by images this cluster is actually running.
//
// Coverage is returned with them, not alongside them in a second call, because
// these findings are silent about every workload OCIDex could not match.
func (h *Handler) ListClusterVulns(ctx context.Context, in *ListClusterVulnsInput) (*ListClusterVulnsOutput, error) {
	if _, err := h.visibleCluster(ctx, in.ID); err != nil {
		return nil, err
	}
	vis := visibilityFilterFromContext(ctx)

	page, err := h.clusterService.RunningVulns(ctx, in.ID, service.RunningVulnParams{
		Severity: in.Severity,
		SortBy:   in.Sort,
		SortDir:  in.Dir,
		Limit:    in.Limit,
		Offset:   in.Offset,
	}, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}
	coverage, err := h.clusterService.Coverage(ctx, in.ID, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &ListClusterVulnsOutput{}
	out.Body.Data = make([]RunningVulnResponse, len(page.Data))
	for i, v := range page.Data {
		out.Body.Data[i] = RunningVulnResponse{
			ID:            v.ID,
			CanonicalID:   v.CanonicalID,
			Severity:      v.Severity,
			CvssScore:     v.CvssScore,
			Summary:       v.Summary,
			WorkloadCount: v.WorkloadCount,
		}
	}
	out.Body.Coverage = WorkloadCoverageResponse{
		Total:        coverage.Total,
		Matched:      coverage.Matched,
		Unknown:      coverage.Unknown,
		Unresolvable: coverage.Unresolvable,
	}
	out.Body.Pagination = PaginationMeta{Total: page.Total, Limit: page.Limit, Offset: page.Offset}
	return out, nil
}

// ListClusterUnknownImages handles GET /api/v1/clusters/{id}/unknown-images:
// the No-SBOM gap grouped by image, each one resolved against the registries of
// the cluster's own namespace.
//
// This is the preview of what ingest would do. It shares its resolver with the
// ingest path, so what the gap list promises and what ingest attempts cannot
// drift apart.
func (h *Handler) ListClusterUnknownImages(ctx context.Context, in *ListClusterUnknownImagesInput) (*ListClusterUnknownImagesOutput, error) {
	if _, err := h.visibleCluster(ctx, in.ID); err != nil {
		return nil, err
	}
	images, err := h.clusterService.UnknownImages(ctx, in.ID, in.Limit, visibilityFilterFromContext(ctx))
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListClusterUnknownImagesOutput{}
	out.Body.Data = make([]UnknownImageResponse, len(images))
	for i, img := range images {
		out.Body.Data[i] = UnknownImageResponse{
			ImageRef:           img.ImageRef,
			ImageDigest:        img.ImageDigest,
			RegistryHost:       img.RegistryHost,
			Repository:         img.Repository,
			WorkloadCount:      img.WorkloadCount,
			PodCount:           img.PodCount,
			SampleK8sNamespace: img.SampleK8sNamespace,
			SampleWorkloadName: img.SampleWorkloadName,
			Reason:             img.Reason,
			RegistryID:         img.RegistryID,
			RegistryName:       img.RegistryName,
		}
	}
	return out, nil
}

// ListVulnWorkloads handles GET /api/v1/vulns/{id}/workloads: which running
// workloads carry a vulnerability, across every cluster the caller can see or
// narrowed to one.
//
// Visibility is enforced by the query through each workload's owning namespace,
// so this needs no cluster pre-check: a cluster the caller cannot see
// contributes no rows rather than an error that would confirm it exists.
func (h *Handler) ListVulnWorkloads(ctx context.Context, in *ListVulnWorkloadsInput) (*ListVulnWorkloadsOutput, error) {
	rows, err := h.clusterService.WorkloadsForVulnerability(ctx, in.ID, in.ClusterID, in.Limit, visibilityFilterFromContext(ctx))
	if err != nil {
		return nil, mapServiceError(err)
	}
	out := &ListVulnWorkloadsOutput{}
	out.Body.Data = make([]RunningWorkloadResponse, len(rows))
	for i, w := range rows {
		out.Body.Data[i] = RunningWorkloadResponse{
			ClusterWorkloadResponse: toWorkloadResponse(w.ClusterWorkload),
			ClusterName:             w.ClusterName,
		}
	}
	return out, nil
}

// visibleCluster loads a cluster and 404s if the caller cannot see its
// namespace. 404 rather than 403 so a private cluster's existence is not
// confirmed to someone who cannot see it.
func (h *Handler) visibleCluster(ctx context.Context, id string) (service.Cluster, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return service.Cluster{}, huma.Error401Unauthorized("not authenticated")
	}
	cluster, err := h.clusterService.Get(ctx, id)
	if err != nil {
		return service.Cluster{}, huma.Error404NotFound("cluster not found")
	}
	ns, err := h.namespaceService.Get(ctx, cluster.NamespaceID)
	if err != nil {
		return service.Cluster{}, huma.Error404NotFound("cluster not found")
	}
	if !canManageNamespace(user, ns) && ns.Visibility == visibilityPrivate {
		return service.Cluster{}, huma.Error404NotFound("cluster not found")
	}
	cluster.NamespaceName = ns.Name
	return cluster, nil
}

// clusterOwnerCheck requires the caller to own the namespace the cluster hangs
// from. This is the ClassOwner enforcement point for every cluster mutation
// including inventory push, which is a mutation even though it reads like a
// report (ADR-044 K8).
func (h *Handler) clusterOwnerCheck(ctx context.Context, id string) error {
	user, ok := UserFromContext(ctx)
	if !ok {
		return huma.Error401Unauthorized("not authenticated")
	}
	cluster, err := h.clusterService.Get(ctx, id)
	if err != nil {
		return huma.Error404NotFound("cluster not found")
	}
	return h.namespaceOwnerCheck(ctx, user, cluster.NamespaceID)
}

func toClusterResponse(c service.Cluster) ClusterResponse {
	out := ClusterResponse{
		ID:            c.ID,
		NamespaceID:   c.NamespaceID,
		NamespaceName: c.NamespaceName,
		Name:          c.Name,
		Description:   c.Description,
		CreatedAt:     c.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     c.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if c.LastSeenAt != nil {
		out.LastSeenAt = c.LastSeenAt.UTC().Format(time.RFC3339)
	}
	return out
}

func toWorkloadResponse(w service.ClusterWorkload) ClusterWorkloadResponse {
	return ClusterWorkloadResponse{
		ID:             w.ID,
		ClusterID:      w.ClusterID,
		K8sNamespace:   w.K8sNamespace,
		WorkloadKind:   w.WorkloadKind,
		WorkloadName:   w.WorkloadName,
		ContainerName:  w.ContainerName,
		ImageRef:       w.ImageRef,
		ImageDigest:    w.ImageDigest,
		PodCount:       w.PodCount,
		FirstSeenAt:    w.FirstSeenAt.UTC().Format(time.RFC3339),
		LastSeenAt:     w.LastSeenAt.UTC().Format(time.RFC3339),
		MatchState:     w.MatchState,
		SBOMID:         w.SBOMID,
		ArtifactID:     w.ArtifactID,
		ArtifactName:   w.ArtifactName,
		ArtifactType:   w.ArtifactType,
		SubjectVersion: w.SubjectVersion,
		Vulns:          toWorkloadVulnCounts(w.Vulns),
	}
}

// toWorkloadVulnCounts preserves the nil the service used to say "never
// assessed"; it does not substitute zeros for it.
func toWorkloadVulnCounts(v *service.VulnCounts) *WorkloadVulnCounts {
	if v == nil {
		return nil
	}
	return &WorkloadVulnCounts{Critical: v.Critical, High: v.High, Medium: v.Medium, Low: v.Low}
}
