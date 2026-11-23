package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// Write requests from agent keys (ADR-0058). Any of them may be held for a
// person's approval: the server answers 202 with a pending action instead of
// doing the work, and these methods return it as Held.

// WriteResult is the outcome of a write that may have been held.
type WriteResult struct {
	// Held is set when the server held the request for approval; nothing ran.
	Held *PendingActionView
	// Body is the response body when the request ran.
	Body json.RawMessage
}

// heldEnvelope is the 202 body of a held request.
type heldEnvelope struct {
	PendingAction *PendingActionView `json:"pendingAction"`
}

// write sends a mutating request, telling the server which MCP tool asked
// (X-OCIDex-Agent-Tool) and the agent's note for an approver.
func (c *httpClient) write(ctx context.Context, method, path string, params url.Values, body any, tool, reason string) (WriteResult, error) {
	var raw json.RawMessage
	headers := http.Header{}
	if tool != "" {
		headers.Set("X-OCIDex-Agent-Tool", tool)
	}
	if reason != "" {
		headers.Set("X-OCIDex-Approval-Reason", reason)
	}
	status, err := c.doWithHeaders(ctx, method, path, params, body, headers, &raw)
	if err != nil {
		return WriteResult{}, err
	}
	if status == http.StatusAccepted {
		var env heldEnvelope
		if json.Unmarshal(raw, &env) == nil && env.PendingAction != nil && env.PendingAction.Id.String() != "00000000-0000-0000-0000-000000000000" {
			return WriteResult{Held: env.PendingAction}, nil
		}
	}
	return WriteResult{Body: raw}, nil
}

func (c *httpClient) WatchArtifact(ctx context.Context, artifactID string, w WriteOpts) (WriteResult, error) {
	return c.write(ctx, http.MethodPut, "/api/v1/users/me/watches/"+url.PathEscape(artifactID), nil, nil, w.Tool, w.Reason)
}

func (c *httpClient) UnwatchArtifact(ctx context.Context, artifactID string, w WriteOpts) (WriteResult, error) {
	return c.write(ctx, http.MethodDelete, "/api/v1/users/me/watches/"+url.PathEscape(artifactID), nil, nil, w.Tool, w.Reason)
}

func (c *httpClient) RequestRegistryScan(ctx context.Context, registryID string, force bool, w WriteOpts) (WriteResult, error) {
	var p url.Values
	if force {
		p = url.Values{"force": {"true"}}
	}
	return c.write(ctx, http.MethodPost, "/api/v1/registries/"+url.PathEscape(registryID)+"/scan", p, nil, w.Tool, w.Reason)
}

func (c *httpClient) RequestClusterIngest(ctx context.Context, clusterID string, digests []string, w WriteOpts) (WriteResult, error) {
	body := map[string]any{"imageDigests": digests}
	return c.write(ctx, http.MethodPost, "/api/v1/clusters/"+url.PathEscape(clusterID)+"/ingest-unknown", nil, body, w.Tool, w.Reason)
}

func (c *httpClient) GetPendingAction(ctx context.Context, id string) (PendingActionView, error) {
	var out PendingActionView
	err := c.request(ctx, http.MethodGet, "/api/v1/approvals/"+url.PathEscape(id), nil, nil, &out)
	return out, err
}

// WriteOpts carries what an agent write says about itself.
type WriteOpts struct {
	// Tool is the MCP tool that made the request, for the audit log.
	Tool string
	// Reason is the agent's note for an approver; shown as untrusted text.
	Reason string
}

func (c *httpClient) ListApprovals(ctx context.Context, status string) ([]PendingActionView, error) {
	var p url.Values
	if status != "" {
		p = url.Values{"status": {status}}
	}
	var out struct {
		Data []PendingActionView `json:"data"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/v1/approvals", p, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}
