package client

import (
	"context"
	"net/http"
	"net/url"
)

// ListSources returns the sources visible to the caller. A non-empty
// namespaceID scopes the list to that namespace.
func (c *httpClient) ListSources(ctx context.Context, namespaceID string) ([]SourceResponse, error) {
	var q url.Values
	if namespaceID != "" {
		q = url.Values{"namespace_id": []string{namespaceID}}
	}
	var out ListSourcesOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/sources", q, nil, &out); err != nil {
		return nil, err
	}
	return derefSlice(out.Data), nil
}

func (c *httpClient) GetSource(ctx context.Context, id string) (SourceResponse, error) {
	var out SourceResponse
	err := c.request(ctx, http.MethodGet, "/api/v1/sources/"+id, nil, nil, &out)
	return out, err
}

func (c *httpClient) CreateSource(ctx context.Context, body CreateSourceInputBody) (SourceResponse, error) {
	var out SourceResponse
	err := c.request(ctx, http.MethodPost, "/api/v1/sources", nil, body, &out)
	return out, err
}

func (c *httpClient) UpdateSource(ctx context.Context, id string, body UpdateSourceInputBody) (SourceResponse, error) {
	var out SourceResponse
	err := c.request(ctx, http.MethodPatch, "/api/v1/sources/"+id, nil, body, &out)
	return out, err
}

func (c *httpClient) DeleteSource(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/sources/"+id, nil, nil, nil)
}
