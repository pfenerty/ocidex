package main

import (
	"context"
	"errors"
	"testing"

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
	return &agent{cfg: cfg, pods: cs.CoreV1(), api: fc}
}

func TestReportPushesEveryNamespaceByDefault(t *testing.T) {
	is := is.New(t)

	var pushed []client.InventoryWorkload
	var pushedCluster string
	fc := &client.FakeClient{
		PutInventoryFn: func(_ context.Context, clusterID string, w []client.InventoryWorkload) (client.PutInventoryOutputBody, error) {
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
		PutInventoryFn: func(_ context.Context, _ string, w []client.InventoryWorkload) (client.PutInventoryOutputBody, error) {
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
		PutInventoryFn: func(_ context.Context, _ string, w []client.InventoryWorkload) (client.PutInventoryOutputBody, error) {
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
		PutInventoryFn: func(_ context.Context, _ string, _ []client.InventoryWorkload) (client.PutInventoryOutputBody, error) {
			return client.PutInventoryOutputBody{}, want
		},
	}

	a := newAgent(t, &config.K8sAgentConfig{ClusterID: "c"}, nil, fc)
	err := a.report(t.Context())
	// Surfaced, not swallowed: --once mode turns this into a non-zero exit, which
	// is how a Job reports failure under ADR-027.
	is.True(errors.Is(err, want))
}
