package client

import (
	"context"
	"net/http"
	"net/url"
)

func (c *httpClient) ListRegistries(ctx context.Context, opts PageOpts) (Page[RegistryResponse], error) {
	var out ListRegistriesOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/registries", pageParams(opts), nil, &out); err != nil {
		return Page[RegistryResponse]{}, err
	}
	return Page[RegistryResponse]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) GetRegistry(ctx context.Context, id string) (RegistryResponse, error) {
	var out RegistryResponse
	err := c.request(ctx, http.MethodGet, "/api/v1/registries/"+id, nil, nil, &out)
	return out, err
}

func (c *httpClient) GetRegistryByName(ctx context.Context, name string) (RegistryResponse, error) {
	var out RegistryResponse
	err := c.request(ctx, http.MethodGet, "/api/v1/registries/by-name/"+url.PathEscape(name), nil, nil, &out)
	return out, err
}

func (c *httpClient) CreateRegistry(ctx context.Context, body CreateRegistryInputBody) (CreateRegistryResponseBody, error) {
	var out CreateRegistryResponseBody
	err := c.request(ctx, http.MethodPost, "/api/v1/registries", nil, body, &out)
	return out, err
}

func (c *httpClient) UpdateRegistry(ctx context.Context, id string, body UpdateRegistryInputBody) (RegistryResponse, error) {
	var out RegistryResponse
	err := c.request(ctx, http.MethodPatch, "/api/v1/registries/"+id, nil, body, &out)
	return out, err
}

func (c *httpClient) DeleteRegistry(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/registries/"+id, nil, nil, nil)
}

func (c *httpClient) ScanRegistry(ctx context.Context, id string) (ScanRegistryOutputBody, error) {
	var out ScanRegistryOutputBody
	err := c.request(ctx, http.MethodPost, "/api/v1/registries/"+id+"/scan", nil, nil, &out)
	return out, err
}

func (c *httpClient) TestRegistryConnection(ctx context.Context, body TestRegistryConnectionInputBody) (TestRegistryConnectionOutputBody, error) {
	var out TestRegistryConnectionOutputBody
	err := c.request(ctx, http.MethodPost, "/api/v1/registries/test-connection", nil, body, &out)
	return out, err
}

func (c *httpClient) RegenerateWebhookSecret(ctx context.Context, id string) (RegenerateWebhookSecretOutputBody, error) {
	var out RegenerateWebhookSecretOutputBody
	err := c.request(ctx, http.MethodPost, "/api/v1/registries/"+id+"/webhook-secret", nil, nil, &out)
	return out, err
}
