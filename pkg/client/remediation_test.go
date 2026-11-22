package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func ptr[T any](v T) *T { return &v }

// Each case pins the path and the exact query a method sends for a set of
// params, which is where a hand-written wrapper over a generated *Params struct
// goes wrong: a misspelled key is silently ignored by the server.
func TestRemediationReadsRequest(t *testing.T) {
	cases := []struct {
		name      string
		wantPath  string
		wantQuery string
		body      string
		call      func(c Client) error
	}{
		{
			name:      "artifact vulns",
			wantPath:  "/api/v1/artifacts/art-1/vulns",
			wantQuery: "dir=desc&limit=5&offset=10&severity=CRITICAL&sort=cvssScore&versionScope=3&vuln=CVE-1",
			body:      `{"data":[],"pagination":{"total":0,"limit":5,"offset":10},"totalVersions":4,"versionScope":3}`,
			call: func(c Client) error {
				out, err := c.ListArtifactVulns(context.Background(), "art-1", ListArtifactVulnsParams{
					Severity:     ptr(ListArtifactVulnsParamsSeverityCRITICAL),
					Vuln:         ptr("CVE-1"),
					Sort:         ptr(ListArtifactVulnsParamsSortCvssScore),
					Dir:          ptr(ListArtifactVulnsParamsDir("desc")),
					VersionScope: ptr(int32(3)),
					Limit:        ptr(int32(5)),
					Offset:       ptr(int32(10)),
				})
				if err == nil && out.TotalVersions != 4 {
					t.Errorf("totalVersions = %d", out.TotalVersions)
				}
				return err
			},
		},
		{
			name:      "sbom vulns unset params send nothing",
			wantPath:  "/api/v1/sboms/sb-1/vulns",
			wantQuery: "",
			body: `{"data":[{"id":"v","canonicalId":"CVE-2","severity":"HIGH","affectedPackageCount":1,` +
				`"affectedPackages":[{"name":"openssl","version":"3.0.1","fixedVersion":"3.0.2","fixState":"fixed","matchedViaSource":false}]}],` +
				`"pagination":{"total":1,"limit":50,"offset":0}}`,
			call: func(c Client) error {
				page, err := c.ListSBOMVulns(context.Background(), "sb-1", ListSbomVulnsParams{})
				if err == nil && (len(page.Data) != 1 || page.Pagination.Total != 1) {
					t.Errorf("page = %+v", page)
				}
				return err
			},
		},
		{
			name:      "top vulns",
			wantPath:  "/api/v1/vulns",
			wantQuery: "q=log4j&sortDir=desc",
			body:      `{"data":[],"pagination":{"total":0,"limit":50,"offset":0}}`,
			call: func(c Client) error {
				_, err := c.ListTopVulnerabilities(context.Background(), ListTopVulnerabilitiesParams{
					Q: ptr("log4j"), SortDir: ptr(ListTopVulnerabilitiesParamsSortDir("desc")),
				})
				return err
			},
		},
		{
			name:      "my vulns",
			wantPath:  "/api/v1/users/me/vulns",
			wantQuery: "limit=7",
			body:      `{"data":[],"pagination":{"total":0,"limit":7,"offset":0}}`,
			call: func(c Client) error {
				_, err := c.ListMyVulnerabilities(context.Background(), ListMyVulnerabilitiesParams{Limit: ptr(int32(7))})
				return err
			},
		},
		{
			name:      "vulnerability workloads escapes id",
			wantPath:  "/api/v1/vulns/GHSA-aaaa-bbbb-cccc/workloads",
			wantQuery: "clusterId=cl-1",
			body:      `{"data":[]}`,
			call: func(c Client) error {
				_, err := c.ListVulnerabilityWorkloads(context.Background(), "GHSA-aaaa-bbbb-cccc",
					ListVulnerabilityWorkloadsParams{ClusterId: ptr("cl-1")})
				return err
			},
		},
		{
			name:     "artifact contains",
			wantPath: "/api/v1/artifacts/art-1/contains",
			body:     `{"contains":[]}`,
			call: func(c Client) error {
				_, err := c.GetArtifactContains(context.Background(), "art-1")
				return err
			},
		},
		{
			name:     "artifact usages",
			wantPath: "/api/v1/artifacts/art-1/usages",
			body:     `{"usages":[]}`,
			call: func(c Client) error {
				_, err := c.GetArtifactUsages(context.Background(), "art-1")
				return err
			},
		},
		{
			name:      "cluster workloads page",
			wantPath:  "/api/v1/clusters/cl-1/workloads",
			wantQuery: "k8sNamespace=prod&matchState=exact&q=api",
			body:      `{"data":[],"coverage":{},"pagination":{"total":0,"limit":50,"offset":0}}`,
			call: func(c Client) error {
				_, err := c.ListClusterWorkloadsPage(context.Background(), "cl-1", ListClusterWorkloadsParams{
					K8sNamespace: ptr("prod"),
					MatchState:   ptr(ListClusterWorkloadsParamsMatchState("exact")),
					Q:            ptr("api"),
				})
				return err
			},
		},
		{
			name:      "cluster images",
			wantPath:  "/api/v1/clusters/cl-1/images",
			wantQuery: "matchState=unknown",
			body:      `{"data":[],"coverage":{},"pagination":{"total":0,"limit":50,"offset":0}}`,
			call: func(c Client) error {
				_, err := c.ListClusterImages(context.Background(), "cl-1", ListClusterImagesParams{
					MatchState: ptr(ListClusterImagesParamsMatchStateUnknown),
				})
				return err
			},
		},
		{
			name:      "cluster vulns",
			wantPath:  "/api/v1/clusters/cl-1/vulns",
			wantQuery: "severity=HIGH",
			body:      `{"data":[],"coverage":{},"pagination":{"total":0,"limit":50,"offset":0}}`,
			call: func(c Client) error {
				_, err := c.ListClusterVulns(context.Background(), "cl-1", ListClusterVulnsParams{
					Severity: ptr(ListClusterVulnsParamsSeverity("HIGH")),
				})
				return err
			},
		},
		{
			name:      "cluster unknown images",
			wantPath:  "/api/v1/clusters/cl-1/unknown-images",
			wantQuery: "offset=20",
			body:      `{"data":[],"hosts":[],"pagination":{"total":0,"limit":50,"offset":20},"reasons":{},"scanningEnabled":true}`,
			call: func(c Client) error {
				_, err := c.ListClusterUnknownImages(context.Background(), "cl-1", ListClusterUnknownImagesParams{Offset: ptr(int32(20))})
				return err
			},
		},
		{
			name:      "sbom drift",
			wantPath:  "/api/v1/sboms/sb-1/drift",
			wantQuery: "cursor=abc",
			body:      `{"data":[],"pagination":{}}`,
			call: func(c Client) error {
				_, err := c.ListSBOMDriftHistory(context.Background(), "sb-1", ListSbomDriftHistoryParams{Cursor: ptr("abc")})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				is.Equal(r.Method, http.MethodGet)
				is.Equal(r.URL.EscapedPath(), tc.wantPath)
				is.Equal(r.URL.RawQuery, tc.wantQuery)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			is.NoErr(tc.call(newTestClient(srv)))
		})
	}
}
