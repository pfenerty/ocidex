package client

import (
	"context"
	"net/http"
)

// JobFilter narrows a scan job listing. A zero value lists every state.
type JobFilter struct {
	// State is one of queued, running, succeeded, or failed.
	State string
}

func (c *httpClient) ListJobs(ctx context.Context, filter JobFilter, opts PageOpts) (Page[ScanJobResponse], error) {
	p := pageParams(opts)
	if filter.State != "" {
		p.Set("state", filter.State)
	}
	var out ListScanJobsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/jobs", p, nil, &out); err != nil {
		return Page[ScanJobResponse]{}, err
	}
	return Page[ScanJobResponse]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

// RetryJob resets a failed scan job back to queued. Admin-only, and the server
// returns no body: success is the absence of an error.
func (c *httpClient) RetryJob(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/api/v1/admin/jobs/"+id+"/retry", nil, nil, nil)
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
