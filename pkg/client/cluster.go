package client

import (
	"context"
	"net/http"
	"net/url"
)

// ListClusters returns the clusters visible to the caller. A non-empty
// namespaceID scopes the list to that namespace.
func (c *httpClient) ListClusters(ctx context.Context, namespaceID string) ([]ClusterResponse, error) {
	var q url.Values
	if namespaceID != "" {
		q = url.Values{"namespaceId": []string{namespaceID}}
	}
	var out ListClustersOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/clusters", q, nil, &out); err != nil {
		return nil, err
	}
	return derefSlice(out.Data), nil
}

func (c *httpClient) GetCluster(ctx context.Context, id string) (ClusterResponse, error) {
	var out ClusterResponse
	err := c.request(ctx, http.MethodGet, "/api/v1/clusters/"+id, nil, nil, &out)
	return out, err
}

func (c *httpClient) CreateCluster(ctx context.Context, body CreateClusterInputBody) (ClusterResponse, error) {
	var out ClusterResponse
	err := c.request(ctx, http.MethodPost, "/api/v1/clusters", nil, body, &out)
	return out, err
}

func (c *httpClient) UpdateCluster(ctx context.Context, id string, body UpdateClusterInputBody) (ClusterResponse, error) {
	var out ClusterResponse
	err := c.request(ctx, http.MethodPatch, "/api/v1/clusters/"+id, nil, body, &out)
	return out, err
}

func (c *httpClient) DeleteCluster(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/clusters/"+id, nil, nil, nil)
}

// PutInventory pushes a complete inventory snapshot. Workloads absent from the
// body are deleted server-side, so callers must send everything they observed —
// including an empty slice, which legitimately means "running nothing". agent
// is the reporter's self-description and may be nil.
func (c *httpClient) PutInventory(ctx context.Context, clusterID string, workloads []InventoryWorkload, agent *InventoryAgent) (PutInventoryOutputBody, error) {
	// Non-nil even when empty: the field is `json:"workloads"` without omitempty,
	// so a nil slice would serialize as null, and null is not the same message as
	// an empty snapshot.
	if workloads == nil {
		workloads = []InventoryWorkload{}
	}
	body := PutInventoryInputBody{Workloads: &workloads, Agent: agent}
	var out PutInventoryOutputBody
	err := c.request(ctx, http.MethodPost, "/api/v1/clusters/"+clusterID+"/inventory", nil, body, &out)
	return out, err
}

// ListClusterWorkloads returns what a cluster last reported running, together
// with the coverage counts. Both are returned because a caller acting on the
// rows alone cannot tell "nothing vulnerable" from "nothing matched".
func (c *httpClient) ListClusterWorkloads(ctx context.Context, clusterID string) ([]ClusterWorkloadResponse, WorkloadCoverageResponse, error) {
	var out ListClusterWorkloadsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/clusters/"+clusterID+"/workloads", nil, nil, &out); err != nil {
		return nil, WorkloadCoverageResponse{}, err
	}
	return derefSlice(out.Data), out.Coverage, nil
}

// ListClusterWorkloadsPage is ListClusterWorkloads with the endpoint's filters,
// sorting and paging. The body is returned whole because the coverage counts and
// the pagination both qualify the rows.
func (c *httpClient) ListClusterWorkloadsPage(ctx context.Context, clusterID string, params ListClusterWorkloadsParams) (ListClusterWorkloadsOutputBody, error) {
	p := url.Values{}
	setOptional(p, "k8sNamespace", params.K8sNamespace)
	setEnum(p, "matchState", params.MatchState)
	setOptional(p, "q", params.Q)
	setEnum(p, "sort", params.Sort)
	setEnum(p, "dir", params.Dir)
	setInt32(p, "limit", params.Limit)
	setInt32(p, "offset", params.Offset)
	var out ListClusterWorkloadsOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/clusters/"+clusterID+"/workloads", p, nil, &out)
	return out, err
}

// ListClusterImages returns the cluster's inventory grouped by image, each
// joined to its matched artifact and SBOM and carrying that SBOM's severity
// counts.
func (c *httpClient) ListClusterImages(ctx context.Context, clusterID string, params ListClusterImagesParams) (ListClusterImagesOutputBody, error) {
	p := url.Values{}
	setOptional(p, "k8sNamespace", params.K8sNamespace)
	setEnum(p, "matchState", params.MatchState)
	setOptional(p, "q", params.Q)
	setEnum(p, "sort", params.Sort)
	setEnum(p, "dir", params.Dir)
	setInt32(p, "limit", params.Limit)
	setInt32(p, "offset", params.Offset)
	var out ListClusterImagesOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/clusters/"+clusterID+"/images", p, nil, &out)
	return out, err
}

// ListClusterVulns returns the advisories carried by images the cluster is
// running, worst first, each with the number of workloads exposed.
func (c *httpClient) ListClusterVulns(ctx context.Context, clusterID string, params ListClusterVulnsParams) (ListClusterVulnsOutputBody, error) {
	p := url.Values{}
	setEnum(p, "severity", params.Severity)
	setEnum(p, "sort", params.Sort)
	setEnum(p, "dir", params.Dir)
	setInt32(p, "limit", params.Limit)
	setInt32(p, "offset", params.Offset)
	var out ListClusterVulnsOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/clusters/"+clusterID+"/vulns", p, nil, &out)
	return out, err
}

// ListClusterUnknownImages returns the cluster's coverage gap: running images
// with no SBOM, grouped by image and resolved against the configured
// registries, with the reason each one is unmatched.
func (c *httpClient) ListClusterUnknownImages(ctx context.Context, clusterID string, params ListClusterUnknownImagesParams) (ListClusterUnknownImagesOutputBody, error) {
	p := url.Values{}
	setInt32(p, "limit", params.Limit)
	setInt32(p, "offset", params.Offset)
	var out ListClusterUnknownImagesOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/clusters/"+clusterID+"/unknown-images", p, nil, &out)
	return out, err
}
