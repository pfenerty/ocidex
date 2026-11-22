package main

import (
	"context"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const clusterUUID = "22222222-2222-2222-2222-222222222222"

func clustersFixture() []client.ClusterResponse {
	return []client.ClusterResponse{
		{Id: clusterUUID, Name: "homelab", NamespaceName: strptr("pfenerty"),
			Health:  client.ClusterHealthResponse{State: "healthy"},
			Summary: &client.ClusterSummaryResponse{RunningCriticals: 3, Coverage: client.WorkloadCoverageResponse{Total: 40, Matched: 30, Unknown: 10}}},
		{Id: "33333333-3333-3333-3333-333333333333", Name: "edge", NamespaceName: strptr("acme"), Health: client.ClusterHealthResponse{State: "stale"}},
		{Id: "44444444-4444-4444-4444-444444444444", Name: "edge", NamespaceName: strptr("other"), Health: client.ClusterHealthResponse{State: "healthy"}},
	}
}

func TestListClusters(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{ListClustersFn: func(context.Context, string) ([]client.ClusterResponse, error) { return clustersFixture(), nil }}
	res := callTool(t, connect(t, api), "ocidex_list_clusters", nil)
	i.True(!res.IsError)
	var out listClustersOutput
	structured(t, resultText(res), &out)
	i.Equal(len(out.Clusters), 3)
	i.Equal(out.Clusters[0].RunningCriticals, int64(3))
	i.Equal(out.Clusters[0].Coverage.Unknown, int64(10))
	i.Equal(out.Clusters[1].Health, "stale")
}

// A name resolves through the visible list; the API itself only takes ids.
func TestClusterVulnerabilitiesResolvesNameAndSortsByWorkloads(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListClustersFn: func(context.Context, string) ([]client.ClusterResponse, error) { return clustersFixture(), nil },
		ListClusterVulnsFn: func(_ context.Context, id string, p client.ListClusterVulnsParams) (client.ListClusterVulnsOutputBody, error) {
			i.Equal(id, clusterUUID)
			i.Equal(string(*p.Sort), "workloadCount")
			i.Equal(string(*p.Dir), "desc")
			i.Equal(string(*p.Severity), "HIGH")
			return client.ListClusterVulnsOutputBody{
				Data:       sliceptr([]client.RunningVulnResponse{{CanonicalId: "CVE-1", Severity: strptr("HIGH"), WorkloadCount: 12}}),
				Pagination: client.PaginationMeta{Total: 1, Limit: 50},
				Coverage:   client.WorkloadCoverageResponse{Total: 40, Unknown: 10},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_cluster_vulnerabilities",
		map[string]any{"cluster": "HomeLab", "sort": "workloads", "severity": "high"})
	i.True(!res.IsError)
	var out clusterVulnsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Vulnerabilities[0].WorkloadCount, int64(12))
	i.Equal(out.Coverage.Unknown, int64(10))
}

func TestClusterNameAmbiguousListsCandidates(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{ListClustersFn: func(context.Context, string) ([]client.ClusterResponse, error) { return clustersFixture(), nil }}
	res := callTool(t, connect(t, api), "ocidex_cluster_images", map[string]any{"cluster": "edge"})
	i.True(res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, "33333333-3333-3333-3333-333333333333"))
	i.True(strings.Contains(text, "namespace other"))
}

func TestClusterNameNotFound(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{ListClustersFn: func(context.Context, string) ([]client.ClusterResponse, error) { return clustersFixture(), nil }}
	res := callTool(t, connect(t, api), "ocidex_cluster_workloads", map[string]any{"cluster": "prod"})
	i.True(res.IsError)
	i.True(strings.Contains(resultText(res), "ocidex_list_clusters"))
}

// A UUID goes straight through without listing clusters.
func TestClusterImagesByIDSortsWorstFirstAndChainsToSBOM(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListClustersFn: func(context.Context, string) ([]client.ClusterResponse, error) {
			t.Fatal("a UUID must not trigger a cluster listing")
			return nil, nil
		},
		ListClusterImagesFn: func(_ context.Context, id string, p client.ListClusterImagesParams) (client.ListClusterImagesOutputBody, error) {
			i.Equal(id, clusterUUID)
			i.Equal(string(*p.Sort), "vulnCount")
			i.Equal(string(*p.MatchState), "exact")
			i.Equal(*p.K8sNamespace, "prod")
			return client.ListClusterImagesOutputBody{
				Data: sliceptr([]client.ClusterImageResponse{{
					ImageRef: "ghcr.io/acme/api:1.2", MatchState: "exact", ArtifactId: strptr("art-1"), SbomId: strptr("sb-1"),
					SubjectVersion: strptr("1.2"), Vulns: &client.WorkloadVulnCounts{Critical: 2}, WorkloadCount: 3,
					SampleNamespace: strptr("prod"), SampleWorkload: strptr("api"),
				}}),
				Pagination: client.PaginationMeta{Total: 1, Limit: 50},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_cluster_images",
		map[string]any{"cluster": clusterUUID, "match_state": "exact", "k8s_namespace": "prod"})
	i.True(!res.IsError)
	var out clusterImagesOutput
	structured(t, resultText(res), &out)
	img := out.Images[0]
	i.Equal(img.SBOMID, "sb-1")
	i.Equal(img.Vulns.Critical, int64(2))
	i.Equal(img.SampleWorkload, "prod/api")
}

func TestClusterInventoryRejectsUnknownMatchState(t *testing.T) {
	i := is.New(t)
	res := callTool(t, connect(t, &client.FakeClient{}), "ocidex_cluster_images",
		map[string]any{"cluster": clusterUUID, "match_state": "clean"})
	i.True(res.IsError)
}

func TestClusterWorkloads(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListClusterWorkloadsPageFn: func(_ context.Context, _ string, p client.ListClusterWorkloadsParams) (client.ListClusterWorkloadsOutputBody, error) {
			i.Equal(*p.Q, "api")
			return client.ListClusterWorkloadsOutputBody{
				Data: sliceptr([]client.ClusterWorkloadResponse{{
					K8sNamespace: "prod", WorkloadKind: "Deployment", WorkloadName: "api", ContainerName: "app",
					ImageRef: "ghcr.io/acme/api:1.2", MatchState: "exact", PodCount: 3,
				}}),
				Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_cluster_workloads", map[string]any{"cluster": clusterUUID, "query": "api"})
	i.True(!res.IsError)
	var out clusterWorkloadsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Workloads[0].WorkloadKind, "Deployment")
}

func TestClusterCoverageGaps(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListClusterUnknownImagesFn: func(context.Context, string, client.ListClusterUnknownImagesParams) (client.ListClusterUnknownImagesOutputBody, error) {
			return client.ListClusterUnknownImagesOutputBody{
				Data: sliceptr([]client.UnknownImageResponse{{
					ImageRef: "quay.io/x/y:1", ImageDigest: "sha256:abc", Reason: "unauthorized", WorkloadCount: 2,
					SampleK8sNamespace: strptr("infra"), SampleWorkloadName: strptr("y"),
				}}),
				Hosts:           sliceptr([]client.UnknownHostResponse{{Scope: "quay.io/x", Reason: "unauthorized", ImageCount: 1}}),
				Reasons:         client.UnknownImageReasonCounts{Unauthorized: 1},
				ScanningEnabled: true,
				Pagination:      client.PaginationMeta{Total: 1},
			}, nil
		},
	}
	res := callTool(t, connect(t, api), "ocidex_cluster_coverage_gaps", map[string]any{"cluster": clusterUUID})
	i.True(!res.IsError)
	var out coverageGapsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Images[0].SampleWorkload, "infra/y")
	i.Equal(out.Hosts[0].Scope, "quay.io/x")
	i.Equal(out.Reasons["unauthorized"], int64(1))
}

func TestVulnerabilityWorkloadsAcrossClustersAndScoped(t *testing.T) {
	i := is.New(t)
	var gotCluster *string
	api := &client.FakeClient{
		ListClustersFn: func(context.Context, string) ([]client.ClusterResponse, error) { return clustersFixture(), nil },
		ListVulnerabilityWorkloadsFn: func(_ context.Context, vuln string, p client.ListVulnerabilityWorkloadsParams) ([]client.RunningWorkloadResponse, error) {
			i.Equal(vuln, "CVE-2024-3094")
			gotCluster = p.ClusterId
			return []client.RunningWorkloadResponse{{ClusterName: "homelab", K8sNamespace: "prod", WorkloadName: "api", MatchState: "exact"}}, nil
		},
	}
	session := connect(t, api)

	res := callTool(t, session, "ocidex_vulnerability_workloads", map[string]any{"vuln_id": "CVE-2024-3094"})
	i.True(!res.IsError)
	i.True(gotCluster == nil)

	res = callTool(t, session, "ocidex_vulnerability_workloads", map[string]any{"vuln_id": "CVE-2024-3094", "cluster": "homelab"})
	i.True(!res.IsError)
	i.Equal(*gotCluster, clusterUUID)
	var out vulnWorkloadsOutput
	structured(t, resultText(res), &out)
	i.Equal(out.Workloads[0].ClusterName, "homelab")
}
