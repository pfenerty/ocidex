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
		q = url.Values{"namespace_id": []string{namespaceID}}
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
// including an empty slice, which legitimately means "running nothing".
func (c *httpClient) PutInventory(ctx context.Context, clusterID string, workloads []InventoryWorkload) (PutInventoryOutputBody, error) {
	// Non-nil even when empty: the field is `json:"workloads"` without omitempty,
	// so a nil slice would serialize as null, and null is not the same message as
	// an empty snapshot.
	if workloads == nil {
		workloads = []InventoryWorkload{}
	}
	body := PutInventoryInputBody{Workloads: &workloads}
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
