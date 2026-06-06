package client

import (
	"context"
	"net/http"
)

func (c *httpClient) ListJobs(ctx context.Context, opts PageOpts) (Page[ScanJobResponse], error) {
	var out ListScanJobsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/jobs", pageParams(opts), nil, &out); err != nil {
		return Page[ScanJobResponse]{}, err
	}
	return Page[ScanJobResponse]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) GetJob(ctx context.Context, id string) (ScanJobResponse, error) {
	var out ScanJobResponse
	err := c.request(ctx, http.MethodGet, "/api/v1/jobs/"+id, nil, nil, &out)
	return out, err
}

func (c *httpClient) GetDashboardStats(ctx context.Context) (DashboardStatsOutputBody, error) {
	var out DashboardStatsOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/stats", nil, nil, &out)
	return out, err
}
