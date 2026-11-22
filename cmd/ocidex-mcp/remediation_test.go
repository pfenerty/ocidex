package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

// structured decodes a tool's structured output into v, which is the contract
// the output schema promises; asserting on it is sturdier than substring
// checks on the rendered text.
func structured(t *testing.T, text string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(text), v); err != nil {
		t.Fatalf("decoding tool output %q: %v", text, err)
	}
}

func TestArtifactFindingsNormalisesSeverityAndMapsVersions(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListArtifactVulnsFn: func(_ context.Context, id string, p client.ListArtifactVulnsParams) (client.ListArtifactVulnsOutputBody, error) {
			i.Equal(id, "art-1")
			i.Equal(string(*p.Severity), "CRITICAL") // a model's lowercase becomes the API's enum
			i.Equal(*p.VersionScope, int32(1))
			i.Equal(*p.Limit, int32(defaultSearchLimit))
			return client.ListArtifactVulnsOutputBody{
				Data: sliceptr([]client.ArtifactVulnEntry{{
					CanonicalId: "CVE-2024-1", Severity: "CRITICAL", AffectedVersionCount: 1,
					AffectedVersions: sliceptr([]client.ArtifactVulnVersion{{Version: "1.2.0", SbomId: "sb-9", PackageNames: sliceptr([]string{"openssl"})}}),
				}}),
				Pagination:    client.PaginationMeta{Total: 1, Limit: 50},
				VersionScope:  1,
				TotalVersions: 7,
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_artifact_findings",
		map[string]any{"artifact_id": "art-1", "severity": "critical", "version_scope": 1})
	i.True(!res.IsError)
	var out artifactFindingsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.TotalVersions, int64(7))
	i.Equal(out.Findings[0].AffectedVersions[0].SBOMID, "sb-9")
}

func TestFindingsRejectUnknownSeverity(t *testing.T) {
	i := is.New(t)
	res := callTool(t, connect(t, &client.FakeClient{}), "ocidex_sbom_findings",
		map[string]any{"sbom_id": "sb-1", "severity": "severe"})
	i.True(res.IsError)
	i.True(strings.Contains(resultText(res), "critical, high, medium, low, unknown"))
}

func sbomFindingsFixture() []client.SBOMVulnEntry {
	openssl := func(fixed, state string) client.SBOMVulnPackage {
		p := client.SBOMVulnPackage{Name: "openssl", Version: strptr("3.0.1"), Purl: "pkg:apk/wolfi/openssl@3.0.1"}
		if fixed != "" {
			p.FixedVersion = strptr(fixed)
		}
		if state != "" {
			p.FixState = strptr(state)
		}
		return p
	}
	zlib := client.SBOMVulnPackage{Name: "zlib", Version: strptr("1.2.13"), Purl: "pkg:apk/wolfi/zlib@1.2.13", FixState: strptr("wont-fix")}
	return []client.SBOMVulnEntry{
		{CanonicalId: "CVE-A", Severity: "HIGH", AffectedPackages: sliceptr([]client.SBOMVulnPackage{openssl("3.0.2", "fixed")})},
		{CanonicalId: "CVE-B", Severity: "CRITICAL", AffectedPackages: sliceptr([]client.SBOMVulnPackage{zlib})},
		{CanonicalId: "CVE-C", Severity: "MEDIUM", AffectedPackages: sliceptr([]client.SBOMVulnPackage{openssl("3.0.8", "fixed")})},
		{CanonicalId: "CVE-D", Severity: "LOW", AffectedPackages: sliceptr([]client.SBOMVulnPackage{openssl("3.0.2", "fixed")})},
	}
}

func TestSBOMFindingsByFindingCarriesFixState(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListSBOMVulnsFn: func(_ context.Context, id string, _ client.ListSbomVulnsParams) (client.Page[client.SBOMVulnEntry], error) {
			i.Equal(id, "sb-1")
			return client.Page[client.SBOMVulnEntry]{Data: sbomFindingsFixture(), Pagination: client.PaginationMeta{Total: 4, Limit: 50}}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_sbom_findings", map[string]any{"sbom_id": "sb-1"})
	i.True(!res.IsError)
	var out sbomFindingsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.GroupBy, "finding")
	i.Equal(len(out.Findings), 4)
	i.Equal(out.Findings[1].AffectedPackages[0].FixState, "wont-fix")
	i.Equal(out.Findings[0].AffectedPackages[0].FixedVersion, "3.0.2")
}

// The package rollup must see every finding, not the first page, or a plan
// would miss upgrades; the fake serves the fixture two rows at a time to prove
// the tool pages through it.
func TestSBOMFindingsByPackagePagesAndRollsUp(t *testing.T) {
	i := is.New(t)
	all := sbomFindingsFixture()
	calls := 0
	api := &client.FakeClient{
		ListSBOMVulnsFn: func(_ context.Context, _ string, p client.ListSbomVulnsParams) (client.Page[client.SBOMVulnEntry], error) {
			calls++
			off := int(*p.Offset)
			end := min(off+2, len(all))
			return client.Page[client.SBOMVulnEntry]{Data: all[off:end], Pagination: client.PaginationMeta{Total: int64(len(all)), Limit: 2, Offset: int32(off)}}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_sbom_findings", map[string]any{"sbom_id": "sb-1", "group_by": "package"})
	i.True(!res.IsError)
	i.Equal(calls, 2)

	var out sbomFindingsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Total, int64(2))
	// zlib carries the critical, so it sorts first despite fewer advisories.
	i.Equal(out.Packages[0].Name, "zlib")
	i.Equal(out.Packages[0].UnfixedCount, 1)
	i.Equal(out.Packages[0].WontFixCount, 1)
	ossl := out.Packages[1]
	i.Equal(ossl.AdvisoryCount, 3)
	i.Equal(ossl.WorstSeverity, "HIGH")
	i.Equal(ossl.FixedVersions, []string{"3.0.2", "3.0.8"}) // distinct, first-seen order
	i.Equal(ossl.UnfixedCount, 0)
}

func TestSBOMFindingsRejectsUnknownGrouping(t *testing.T) {
	i := is.New(t)
	res := callTool(t, connect(t, &client.FakeClient{}), "ocidex_sbom_findings",
		map[string]any{"sbom_id": "sb-1", "group_by": "severity"})
	i.True(res.IsError)
}

func TestListArtifactVersions(t *testing.T) {
	i := is.New(t)
	created := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	api := &client.FakeClient{
		ListArtifactVersionsFn: func(_ context.Context, id string, opts client.PageOpts) (client.Page[client.ArtifactVersionSummary], error) {
			i.Equal(id, "art-1")
			i.Equal(opts.Limit, int32(defaultRootLimit))
			return client.Page[client.ArtifactVersionSummary]{
				Data: []client.ArtifactVersionSummary{{
					ImageVersion: strptr("2.0.0"), SbomId: "sb-2", CreatedAt: created, VersionKey: "2.0.0",
					Vulns: &client.VulnSummary{Critical: 2, Total: 9},
				}},
				Pagination: client.PaginationMeta{Total: 1, Limit: 20},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_list_artifact_versions", map[string]any{"artifact_id": "art-1"})
	i.True(!res.IsError)
	var out listArtifactVersionsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Versions[0].SBOMID, "sb-2")
	i.Equal(out.Versions[0].Critical, int64(2))
	i.Equal(out.Versions[0].CreatedAt, "2026-11-01T12:00:00Z")
}

func TestListSBOMComponentsFiltersSortsAndPages(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListSBOMComponentsFn: func(context.Context, string) ([]client.ComponentSummary, error) {
			return []client.ComponentSummary{
				{Id: "c1", Name: "busybox", VulnCount: int64ptr(0), IsDirect: true},
				{Id: "c2", Name: "openssl", VulnCount: int64ptr(3), MaxSeverity: strptr("high")},
				{Id: "c3", Name: "zlib", VulnCount: int64ptr(1), MaxSeverity: strptr("critical")},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_list_sbom_components",
		map[string]any{"sbom_id": "sb-1", "vulnerable_only": true, "limit": 1})
	i.True(!res.IsError)
	var out listSBOMComponentsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Total, int64(2))
	i.Equal(len(out.Components), 1)
	i.Equal(out.Components[0].ID, "c3") // critical before high
}

func TestArtifactLineage(t *testing.T) {
	i := is.New(t)
	notCurrent := false
	api := &client.FakeClient{
		GetArtifactContainsFn: func(context.Context, string) ([]client.ArtifactRelation, error) {
			return []client.ArtifactRelation{{ArtifactId: "base-1", ArtifactName: "cgr.dev/chainguard/static", SbomId: "sb-b",
				MatchedVersion: strptr("2024.1"), CurrentVersion: strptr("2026.11"), IsCurrent: &notCurrent}}, nil
		},
		GetArtifactUsagesFn: func(context.Context, string) ([]client.ArtifactRelation, error) { return nil, nil },
	}
	res := callTool(t, connect(t, api), "ocidex_artifact_lineage", map[string]any{"artifact_id": "art-1"})
	i.True(!res.IsError)
	var out artifactLineageOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Contains[0].CurrentVersion, "2026.11")
	i.Equal(*out.Contains[0].IsCurrent, false)
	i.True(out.UsedBy != nil) // [] not null: "nothing uses it" is an answer
	i.True(strings.Contains(resultText(res), `"used_by":[]`))
}

func TestComponentVersions(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetComponentVersionsFn: func(_ context.Context, p client.GetComponentVersionsParams) (client.GetComponentVersionsOutputBody, error) {
			i.Equal(p.Name, "openssl")
			return client.GetComponentVersionsOutputBody{
				Versions: sliceptr([]client.ComponentVersionEntry{
					{Id: "o1", Name: "openssl", Version: strptr("3.0.8"), ArtifactName: strptr("ghcr.io/x/api"), SbomId: "sb-1", VulnCount: 0},
				}),
				VersionCount: 2, ArtifactCount: 1, Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_component_versions", map[string]any{"name": "openssl"})
	i.True(!res.IsError)
	var out componentVersionsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Occurrences[0].Version, "3.0.8")
	i.Equal(out.VersionCount, int64(2))
}

func TestGetVulnerabilityCarriesReferences(t *testing.T) {
	i := is.New(t)
	published := time.Date(2024, 3, 29, 0, 0, 0, 0, time.UTC)
	api := &client.FakeClient{
		GetVulnerabilityFn: func(context.Context, string, client.PageOpts) (client.GetVulnerabilityOutputBody, error) {
			return client.GetVulnerabilityOutputBody{Vulnerability: client.VulnDetail{
				CanonicalId: "CVE-2024-3094", Severity: "critical", CvssVector: strptr("CVSS:3.1/AV:N"),
				PublishedAt: &published,
				References:  sliceptr([]client.VulnReference{{Type: "FIX", Url: "https://example.test/patch"}}),
			}}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_get_vulnerability", map[string]any{"vuln_id": "CVE-2024-3094"})
	i.True(!res.IsError)
	var out getVulnerabilityOutput
	structured(t, resultText(res), &out)
	i.Equal(out.References[0].URL, "https://example.test/patch")
	i.Equal(out.CvssVector, "CVSS:3.1/AV:N")
	i.Equal(out.PublishedAt, "2024-03-29T00:00:00Z")
}
