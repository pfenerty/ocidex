package client

import (
	"context"
	"net/http"
	"net/url"
)

// paramName is the server's query key for a component name, shared by the three
// endpoints below so a rename stays a one-line change.
const paramName = "name"

// ComponentFilter narrows a component occurrence search. Name is required by
// the server: this endpoint answers "where does this component appear", one row
// per SBOM it appears in. DistinctComponentFilter is the browse counterpart.
type ComponentFilter struct {
	Name    string
	Group   string
	Version string
}

func (f ComponentFilter) apply(p url.Values) url.Values {
	p.Set(paramName, f.Name)
	if f.Group != "" {
		p.Set("group", f.Group)
	}
	if f.Version != "" {
		p.Set("version", f.Version)
	}
	return p
}

// DistinctComponentFilter narrows the deduplicated component listing. Every
// field is optional; a zero value browses everything visible.
type DistinctComponentFilter struct {
	Name     string
	Group    string
	Type     string
	PurlType string
	Sort     string
	SortDir  string
}

func (f DistinctComponentFilter) apply(p url.Values) url.Values {
	for k, v := range map[string]string{
		paramName: f.Name, "group": f.Group, "type": f.Type,
		"purl_type": f.PurlType, "sort": f.Sort, "sort_dir": f.SortDir,
	} {
		if v != "" {
			p.Set(k, v)
		}
	}
	return p
}

func (c *httpClient) SearchComponents(ctx context.Context, filter ComponentFilter, opts PageOpts) (Page[ComponentSummary], error) {
	var out SearchComponentsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/components", filter.apply(pageParams(opts)), nil, &out); err != nil {
		return Page[ComponentSummary]{}, err
	}
	return Page[ComponentSummary]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) SearchDistinctComponents(ctx context.Context, filter DistinctComponentFilter, opts PageOpts) (Page[DistinctComponentSummary], error) {
	var out SearchDistinctComponentsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/components/distinct", filter.apply(pageParams(opts)), nil, &out); err != nil {
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
	p := url.Values{paramName: {params.Name}}
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
