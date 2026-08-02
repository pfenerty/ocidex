package client

import (
	"context"
	"net/http"
	"net/url"
)

func (c *httpClient) ListNamespaces(ctx context.Context) ([]NamespaceResponse, error) {
	var out ListNamespacesOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/namespaces", nil, nil, &out); err != nil {
		return nil, err
	}
	return derefSlice(out.Data), nil
}

func (c *httpClient) GetNamespace(ctx context.Context, id string) (NamespaceResponse, error) {
	var out NamespaceResponse
	err := c.request(ctx, http.MethodGet, "/api/v1/namespaces/"+id, nil, nil, &out)
	return out, err
}

func (c *httpClient) GetNamespaceByName(ctx context.Context, name string) (NamespaceResponse, error) {
	var out NamespaceResponse
	err := c.request(ctx, http.MethodGet, "/api/v1/namespaces/by-name/"+url.PathEscape(name), nil, nil, &out)
	return out, err
}

func (c *httpClient) CreateNamespace(ctx context.Context, body CreateNamespaceInputBody) (NamespaceResponse, error) {
	var out NamespaceResponse
	err := c.request(ctx, http.MethodPost, "/api/v1/namespaces", nil, body, &out)
	return out, err
}

func (c *httpClient) UpdateNamespace(ctx context.Context, id string, body UpdateNamespaceInputBody) (NamespaceResponse, error) {
	var out NamespaceResponse
	err := c.request(ctx, http.MethodPatch, "/api/v1/namespaces/"+id, nil, body, &out)
	return out, err
}

func (c *httpClient) DeleteNamespace(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/namespaces/"+id, nil, nil, nil)
}
