package client

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
)

func (c *httpClient) IngestSBOM(ctx context.Context, data []byte, params IngestSbomParams) (IngestSBOMOutputBody, error) {
	p := url.Values{}
	if params.Version != nil {
		p.Set("version", *params.Version)
	}
	if params.Architecture != nil {
		p.Set("architecture", *params.Architecture)
	}
	if params.BuildDate != nil {
		p.Set("build_date", *params.BuildDate)
	}
	var out IngestSBOMOutputBody
	err := c.do(ctx, http.MethodPost, "/api/v1/sboms", p, bytes.NewReader(data), "application/octet-stream", &out)
	return out, err
}

func (c *httpClient) GetSBOM(ctx context.Context, id string, includeRaw bool) (SBOMDetail, error) {
	p := url.Values{}
	if includeRaw {
		p.Set("include", "raw")
	}
	var out SBOMDetail
	err := c.request(ctx, http.MethodGet, "/api/v1/sboms/"+id, p, nil, &out)
	return out, err
}

func (c *httpClient) ListSBOMs(ctx context.Context, opts PageOpts) (CursorPage[SBOMSummary], error) {
	var out ListSBOMsOutputBody
	if err := c.request(ctx, http.MethodGet, "/api/v1/sboms", pageParams(opts), nil, &out); err != nil {
		return CursorPage[SBOMSummary]{}, err
	}
	return CursorPage[SBOMSummary]{Data: derefSlice(out.Data), Pagination: out.Pagination}, nil
}

func (c *httpClient) DeleteSBOM(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodDelete, "/api/v1/sboms/"+id, nil, nil, nil)
}

func (c *httpClient) DiffSBOMs(ctx context.Context, fromID, toID string) (ChangelogEntry, error) {
	p := url.Values{"from": {fromID}, "to": {toID}}
	var out ChangelogEntry
	err := c.request(ctx, http.MethodGet, "/api/v1/sboms/diff", p, nil, &out)
	return out, err
}

func (c *httpClient) GetDiffTree(ctx context.Context, fromID, toID string) (DiffTree, error) {
	p := url.Values{"from": {fromID}, "to": {toID}}
	var out DiffTree
	err := c.request(ctx, http.MethodGet, "/api/v1/sboms/diff-tree", p, nil, &out)
	return out, err
}
