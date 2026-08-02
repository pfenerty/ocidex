package client

import (
	"context"
	"net/http"
	"net/url"
)

// ArtifactFilter narrows an artifact listing. A zero value lists artifacts with
// sufficiently enriched SBOMs, which is what the server returns by default.
type ArtifactFilter struct {
	// Type is a CycloneDX component type, e.g. container or application.
	Type string
	// Name matches the artifact name.
	Name string
	// IncludeInsufficient also returns artifacts whose SBOMs are not enriched
	// enough to be trusted, which the server hides unless asked.
	IncludeInsufficient bool
}

func (f ArtifactFilter) apply(p url.Values) url.Values {
	if f.Type != "" {
		p.Set("type", f.Type)
	}
	if f.Name != "" {
		p.Set("name", f.Name)
	}
	if f.IncludeInsufficient {
		p.Set("sufficient", "false")
	}
	return p
}

func (c *httpClient) ListArtifacts(ctx context.Context, filter ArtifactFilter, opts PageOpts) (CursorPage[ArtifactSummary], error) {
	var out ListArtifactsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/artifacts", filter.apply(pageParams(opts)), nil, &out); err != nil {
		return CursorPage[ArtifactSummary]{}, err
	}
	return CursorPage[ArtifactSummary]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) GetArtifact(ctx context.Context, id string) (ArtifactDetail, error) {
	var out ArtifactDetail
	err := c.request(ctx, http.MethodGet, "/api/v1/artifacts/"+id, nil, nil, &out)
	return out, err
}

func (c *httpClient) GetArtifactChangelog(ctx context.Context, id string, params GetArtifactChangelogParams) (Changelog, error) {
	p := url.Values{}
	if params.SubjectVersion != nil {
		p.Set("subject_version", *params.SubjectVersion)
	}
	if params.Arch != nil {
		p.Set("arch", *params.Arch)
	}
	if params.Flavor != nil {
		p.Set("flavor", *params.Flavor)
	}
	var out Changelog
	err := c.request(ctx, http.MethodGet, "/api/v1/artifacts/"+id+"/changelog", p, nil, &out)
	return out, err
}

func (c *httpClient) GetArtifactLicenseSummary(ctx context.Context, id string) (GetArtifactLicenseSummaryOutputBody, error) {
	var out GetArtifactLicenseSummaryOutputBody
	err := c.request(ctx, http.MethodGet, "/api/v1/artifacts/"+id+"/license-summary", nil, nil, &out)
	return out, err
}

func (c *httpClient) ListArtifactSBOMs(ctx context.Context, id string, opts PageOpts) (CursorPage[SBOMSummary], error) {
	var out ListArtifactSBOMsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/artifacts/"+id+"/sboms", pageParams(opts), nil, &out); err != nil {
		return CursorPage[SBOMSummary]{}, err
	}
	return CursorPage[SBOMSummary]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) ListArtifactVersions(ctx context.Context, id string, opts PageOpts) (Page[ArtifactVersionSummary], error) {
	var out ListArtifactVersionsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/artifacts/"+id+"/versions", pageParams(opts), nil, &out); err != nil {
		return Page[ArtifactVersionSummary]{}, err
	}
	return Page[ArtifactVersionSummary]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}
