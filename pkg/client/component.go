package client

import (
	"context"
	"net/http"
	"net/url"
)

func (c *httpClient) SearchComponents(ctx context.Context, query string, opts PageOpts) (Page[ComponentSummary], error) {
	p := pageParams(opts)
	p.Set("name", query)
	var out SearchComponentsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/components", p, nil, &out); err != nil {
		return Page[ComponentSummary]{}, err
	}
	return Page[ComponentSummary]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) SearchDistinctComponents(ctx context.Context, query string, opts PageOpts) (Page[DistinctComponentSummary], error) {
	p := pageParams(opts)
	if query != "" {
		p.Set("name", query)
	}
	var out SearchDistinctComponentsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/components/distinct", p, nil, &out); err != nil {
		return Page[DistinctComponentSummary]{}, err
	}
	return Page[DistinctComponentSummary]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) GetComponent(ctx context.Context, id string) (ComponentDetail, error) {
	var out ComponentDetail
	err := c.request(ctx, http.MethodGet, "/api/v1/components/"+id, nil, nil, &out)
	return out, err
}

func (c *httpClient) GetComponentVersions(ctx context.Context, params GetComponentVersionsParams) (GetComponentVersionsOutputBody, error) {
	p := url.Values{"name": {params.Name}}
	if params.Group != nil {
		p.Set("group", *params.Group)
	}
	if params.Version != nil {
		p.Set("version", *params.Version)
	}
	if params.Type != nil {
		p.Set("type", *params.Type)
	}
	var out GetComponentVersionsOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/components/versions", p, nil, &out)
	return out, err
}

func (c *httpClient) ListComponentPurlTypes(ctx context.Context) ([]string, error) {
	var out ListComponentPurlTypesOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/components/purl-types", nil, nil, &out); err != nil {
		return nil, err
	}
	return derefSlice(out.Types), nil
}

func (c *httpClient) ListSBOMComponents(ctx context.Context, sbomID string) ([]ComponentSummary, error) {
	var out ListSBOMComponentsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/sboms/"+sbomID+"/components", nil, nil, &out); err != nil {
		return nil, err
	}
	return derefSlice(out.Components), nil
}

func (c *httpClient) GetSBOMDependencies(ctx context.Context, sbomID string) (DependencyGraph, error) {
	var out DependencyGraph
	err := c.request(ctx, http.MethodGet, "/api/v1/sboms/"+sbomID+"/dependencies", nil, nil, &out)
	return out, err
}
