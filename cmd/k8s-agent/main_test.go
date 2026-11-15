package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/matryer/is"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newAgent(t *testing.T, cfg *config.K8sAgentConfig, pods []corev1.Pod, fc *client.FakeClient) *agent {
	t.Helper()
	objs := make([]runtime.Object, 0, len(pods))
	for i := range pods {
		objs = append(objs, &pods[i])
	}
	cs := fake.NewClientset(objs...)
	return &agent{cfg: cfg, pods: cs.CoreV1(), discovery: cs.Discovery(), api: fc}
}

func TestReportPushesEveryNamespaceByDefault(t *testing.T) {
	is := is.New(t)

	var pushed []client.InventoryWorkload
	var pushedCluster string
	fc := &client.FakeClient{
		PutInventoryFn: func(_ context.Context, clusterID string, w []client.InventoryWorkload, _ *client.InventoryAgent) (client.PutInventoryOutputBody, error) {
			pushedCluster = clusterID
			pushed = w
			return client.PutInventoryOutputBody{Accepted: int64(len(w))}, nil
		},
	}

	a := newAgent(t, &config.K8sAgentConfig{ClusterID: "cluster-1"}, []corev1.Pod{
		pod("default", "api", withContainer("api", "ghcr.io/x/api:1", "ghcr.io/x/api@"+digestA)),
		pod("kube-system", "dns", withContainer("dns", "registry.k8s.io/coredns:1", "registry.k8s.io/coredns@"+digestB)),
	}, fc)

	is.NoErr(a.report(t.Context()))
	is.Equal(pushedCluster, "cluster-1")
	is.Equal(len(pushed), 2)
}

func TestReportHonoursNamespaceAllowlist(t *testing.T) {
	is := is.New(t)

	var pushed []client.InventoryWorkload
	fc := &client.FakeClient{
		PutInventoryFn: func(_ context.Context, _ string, w []client.InventoryWorkload, _ *client.InventoryAgent) (client.PutInventoryOutputBody, error) {
			pushed = w
			return client.PutInventoryOutputBody{}, nil
		},
	}

	a := newAgent(t, &config.K8sAgentConfig{ClusterID: "c", Namespaces: []string{"default"}}, []corev1.Pod{
		pod("default", "api", withContainer("api", "ghcr.io/x/api:1", "ghcr.io/x/api@"+digestA)),
		pod("kube-system", "dns", withContainer("dns", "registry.k8s.io/coredns:1", "registry.k8s.io/coredns@"+digestB)),
	}, fc)

	is.NoErr(a.report(t.Context()))
	is.Equal(len(pushed), 1)
	is.Equal(pushed[0].K8sNamespace, "default")
}

// TestReportPushesEmptySnapshot pins the property that makes an empty cluster
// distinguishable from a dead agent (ADR-044 K2): the agent must still push,
// because the server stamps last_seen_at on the push and not on the rows.
func TestReportPushesEmptySnapshot(t *testing.T) {
	is := is.New(t)

	called := false
	fc := &client.FakeClient{
		PutInventoryFn: func(_ context.Context, _ string, w []client.InventoryWorkload, _ *client.InventoryAgent) (client.PutInventoryOutputBody, error) {
			called = true
			is.Equal(len(w), 0)
			return client.PutInventoryOutputBody{}, nil
		},
	}

	a := newAgent(t, &config.K8sAgentConfig{ClusterID: "c"}, nil, fc)
	is.NoErr(a.report(t.Context()))
	is.True(called)
}

func TestReportPropagatesPushFailure(t *testing.T) {
	is := is.New(t)

	want := errors.New("boom")
	fc := &client.FakeClient{
		PutInventoryFn: func(_ context.Context, _ string, _ []client.InventoryWorkload, _ *client.InventoryAgent) (client.PutInventoryOutputBody, error) {
			return client.PutInventoryOutputBody{}, want
		},
	}

	a := newAgent(t, &config.K8sAgentConfig{ClusterID: "c"}, nil, fc)
	err := a.report(t.Context())
	// Surfaced, not swallowed: --once mode turns this into a non-zero exit, which
	// is how a Job reports failure under ADR-027.
	is.True(errors.Is(err, want))
}

// TestReportDescribesTheAgent pins the self-report sent with each snapshot
// (ocidex-70eo.3).
func TestReportDescribesTheAgent(t *testing.T) {
	is := is.New(t)

	var got *client.InventoryAgent
	fc := &client.FakeClient{
		PutInventoryFn: func(_ context.Context, _ string, _ []client.InventoryWorkload, a *client.InventoryAgent) (client.PutInventoryOutputBody, error) {
			got = a
			return client.PutInventoryOutputBody{}, nil
		},
	}

	api := pod("default", "api", withContainer("api", "ghcr.io/x/api:1", "ghcr.io/x/api@"+digestA))
	api.Spec.NodeName = "node-a"
	dns := pod("kube-system", "dns", withContainer("dns", "registry.k8s.io/coredns:1", "registry.k8s.io/coredns@"+digestB))
	dns.Spec.NodeName = "node-b"
	again := pod("default", "web", withContainer("web", "ghcr.io/x/web:1", "ghcr.io/x/web@"+digestA))
	again.Spec.NodeName = "node-a"

	cfg := &config.K8sAgentConfig{ClusterID: "c", ReportInterval: 5 * time.Minute, PodName: "agent-0", PodNamespace: "ocidex-agent"}
	a := newAgent(t, cfg, []corev1.Pod{api, dns, again}, fc)

	is.NoErr(a.report(t.Context()))
	is.True(got != nil)
	is.Equal(*got.NodeCount, int32(2))
	is.Equal(*got.ReportIntervalSeconds, int32(300))
	is.Equal(*got.Namespaces, []string{})
	is.Equal(*got.PodName, "agent-0")
	is.Equal(*got.PodNamespace, "ocidex-agent")
	is.True(got.Version != nil && *got.Version != "")
	is.True(got.KubernetesVersion != nil)

	// A one-shot Job has no next report.
	a.oneShot = true
	is.NoErr(a.report(t.Context()))
	is.Equal(*got.ReportIntervalSeconds, int32(0))
}
