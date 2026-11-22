package main

import (
	"context"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

func TestTopVulnerabilitiesCatalogSortedBySBOMs(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListTopVulnerabilitiesFn: func(_ context.Context, p client.ListTopVulnerabilitiesParams) (client.Page[client.TopVulnEntry], error) {
			i.Equal(string(*p.Sort), "affectedSbomCount")
			i.Equal(string(*p.SortDir), "desc")
			i.Equal(string(*p.Severity), "CRITICAL")
			return client.Page[client.TopVulnEntry]{
				Data:       []client.TopVulnEntry{{CanonicalId: "CVE-1", Severity: "CRITICAL", AffectedSbomCount: 40}},
				Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
		ListMyVulnerabilitiesFn: func(context.Context, client.ListMyVulnerabilitiesParams) (client.Page[client.TopVulnEntry], error) {
			t.Fatal("catalog scope must not call the per-owner endpoint")
			return client.Page[client.TopVulnEntry]{}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_top_vulnerabilities", map[string]any{"sort": "sboms", "severity": "critical"})
	i.True(!res.IsError)
	var out topVulnsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Scope, "catalog")
	i.Equal(out.Vulnerabilities[0].AffectedSBOMCount, int64(40))
}

func TestTopVulnerabilitiesMine(t *testing.T) {
	i := is.New(t)
	called := false
	api := &client.FakeClient{
		ListMyVulnerabilitiesFn: func(_ context.Context, p client.ListMyVulnerabilitiesParams) (client.Page[client.TopVulnEntry], error) {
			called = true
			i.Equal(*p.Q, "log4")
			return client.Page[client.TopVulnEntry]{}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_top_vulnerabilities", map[string]any{"mine": true, "query": "log4"})
	i.True(!res.IsError)
	i.True(called)
	var out topVulnsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Scope, "mine")
	i.True(out.Vulnerabilities != nil)
}

func TestTopVulnerabilitiesRejectsUnknownSort(t *testing.T) {
	i := is.New(t)
	res := callTool(t, connect(t, &client.FakeClient{}), "ocidex_top_vulnerabilities", map[string]any{"sort": "popularity"})
	i.True(res.IsError)
}

func TestSearchArtifacts(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListArtifactsFn: func(_ context.Context, f client.ArtifactFilter, opts client.PageOpts) (client.CursorPage[client.ArtifactSummary], error) {
			i.Equal(f.Name, "redis")
			i.Equal(opts.Limit, int32(defaultSearchLimit))
			return client.CursorPage[client.ArtifactSummary]{
				Data:       []client.ArtifactSummary{{Id: "a1", Name: "docker.io/library/redis", Type: "container", Vulns: &client.VulnSummary{Critical: 1, Total: 5}}},
				Pagination: client.CursorMeta{HasMore: true},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_search_artifacts", map[string]any{"name": "redis"})
	i.True(!res.IsError)
	var out searchArtifactsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Artifacts[0].Name, "docker.io/library/redis")
	i.Equal(out.Artifacts[0].Critical, int64(1))
	i.True(out.HasMore)
}

func TestLicenseSummarySortsByComponents(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetArtifactLicenseSummaryFn: func(context.Context, string) (client.GetArtifactLicenseSummaryOutputBody, error) {
			return client.GetArtifactLicenseSummaryOutputBody{
				SbomId: strptr("sb-1"),
				Licenses: sliceptr([]client.LicenseCount{
					{Name: "GPL", Category: "copyleft", ComponentCount: 2},
					{Name: "MIT", Category: "permissive", ComponentCount: 30},
				}),
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_artifact_license_summary", map[string]any{"artifact_id": "a1"})
	i.True(!res.IsError)
	var out licenseSummaryOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Licenses[0].Name, "MIT")
	i.Equal(out.SBOMID, "sb-1")
}

func TestSBOMDrift(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListSBOMDriftHistoryFn: func(_ context.Context, id string, p client.ListSbomDriftHistoryParams) (client.CursorPage[client.ProvenanceDriftSummary], error) {
			i.Equal(id, "sb-1")
			return client.CursorPage[client.ProvenanceDriftSummary]{
				Data: []client.ProvenanceDriftSummary{{
					DetectedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), PreviousStatus: "verified", NewStatus: "unverified", Reason: "signature removed",
				}},
				Pagination: client.CursorMeta{NextCursor: strptr("next")},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_sbom_drift", map[string]any{"sbom_id": "sb-1"})
	i.True(!res.IsError)
	var out sbomDriftOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Events[0].NewStatus, "unverified")
	i.Equal(out.NextCursor, "next")
}

func TestDataFreshness(t *testing.T) {
	i := is.New(t)
	rows := []client.EnrichmentJobSummaryRow{
		{EnricherName: "vuln", State: "succeeded", Count: 100},
		{EnricherName: "vuln", State: "queued", Count: 3},
		{EnricherName: "provenance", State: "succeeded", Count: 90},
		{EnricherName: "provenance", State: "pruned", Count: 5},
	}
	api := &client.FakeClient{
		GetEnrichmentJobsSummaryFn: func(context.Context) ([]client.EnrichmentJobSummaryRow, error) { return rows, nil },
	}
	session := connect(t, api)

	var out dataFreshnessOutput
	structured(t, resultText(callTool(t, session, "ocidex_data_freshness", nil)), &out)
	i.True(!out.Current)
	i.Equal(out.Enrichers[1].Enricher, "vuln") // sorted by name
	i.Equal(out.Enrichers[1].Backlog, int64(3))
	i.Equal(out.Enrichers[0].Backlog, int64(0)) // pruned is not a backlog

	rows = rows[:1]
	structured(t, resultText(callTool(t, session, "ocidex_data_freshness", nil)), &out)
	i.True(out.Current)
}
