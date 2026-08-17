package main

import (
	"strings"
	"testing"

	"github.com/matryer/is"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestNormalizeImageID covers every imageID form in the ADR-044 K3 table plus the
// malformed cases. The K3 rows are marked, because the one that is easy to get
// wrong — `docker://sha256:…` — looks like a perfectly good digest and is not
// one: it is the runtime's local image ID, so accepting it would produce a
// permanently-unknown row that points the operator at the wrong remedy.
func TestNormalizeImageID(t *testing.T) {
	tests := []struct {
		name    string
		imageID string
		want    string
		wantOK  bool
	}{
		{
			name:    "K3 containerd: registry ref with digest",
			imageID: "docker.io/library/nginx@" + digestA,
			want:    digestA, wantOK: true,
		},
		{
			name:    "K3 CRI-O: bare digest",
			imageID: digestA,
			want:    digestA, wantOK: true,
		},
		{
			name:    "K3 dockershim: docker-pullable with digest",
			imageID: "docker-pullable://nginx@" + digestA,
			want:    digestA, wantOK: true,
		},
		{
			name:    "K3 dockershim: docker:// image ID is unresolvable",
			imageID: "docker://" + digestA,
			wantOK:  false,
		},
		{
			name:    "containerd with port in registry host",
			imageID: "localhost:5005/ocidex/api@" + digestB,
			want:    digestB, wantOK: true,
		},
		{
			name:    "ghcr ref with tag and digest",
			imageID: "ghcr.io/pfenerty/ocidex/api:v1.2.3@" + digestA,
			want:    digestA, wantOK: true,
		},
		{
			name:    "upper-case hex is folded, not rejected",
			imageID: "nginx@sha256:" + strings.ToUpper(strings.TrimPrefix(digestA, "sha256:")),
			want:    digestA, wantOK: true,
		},
		{
			name:    "surrounding whitespace is trimmed",
			imageID: "  " + digestA + "\n",
			want:    digestA, wantOK: true,
		},
		{
			name:    "empty",
			imageID: "",
			wantOK:  false,
		},
		{
			name:    "digest too short",
			imageID: "nginx@sha256:abc",
			wantOK:  false,
		},
		{
			name:    "non-hex characters",
			imageID: "nginx@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantOK:  false,
		},
		{
			name:    "unsupported algorithm",
			imageID: "nginx@sha512:" + strings.TrimPrefix(digestA, "sha256:"),
			wantOK:  false,
		},
		{
			name:    "tag only, no digest anywhere",
			imageID: "nginx:1.25",
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			got, ok := normalizeImageID(tc.imageID)
			is.Equal(ok, tc.wantOK)
			is.Equal(got, tc.want)
		})
	}
}

// podOpt mutates a fixture pod.
type podOpt func(*corev1.Pod)

func withOwner(kind, name string, controller bool) podOpt {
	return func(p *corev1.Pod) {
		p.OwnerReferences = append(p.OwnerReferences, metav1.OwnerReference{
			Kind: kind, Name: name, Controller: &controller,
		})
	}
}

// withPodTemplateHash sets the label a Deployment's pods carry, which is what
// makes recovering the Deployment name from the ReplicaSet name exact.
func withPodTemplateHash(hash string) podOpt {
	return func(p *corev1.Pod) {
		if p.Labels == nil {
			p.Labels = map[string]string{}
		}
		p.Labels["pod-template-hash"] = hash
	}
}

func withPhase(phase corev1.PodPhase) podOpt {
	return func(p *corev1.Pod) { p.Status.Phase = phase }
}

func withContainer(name, image, imageID string) podOpt {
	return func(p *corev1.Pod) {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: name, Image: image})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses,
			corev1.ContainerStatus{Name: name, Image: image, ImageID: imageID})
	}
}

func withInitContainer(name, image, imageID string) podOpt {
	return func(p *corev1.Pod) {
		p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: name, Image: image})
		p.Status.InitContainerStatuses = append(p.Status.InitContainerStatuses,
			corev1.ContainerStatus{Name: name, Image: image, ImageID: imageID})
	}
}

func pod(ns, name string, opts ...podOpt) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, o := range opts {
		o(&p)
	}
	return p
}

func TestOwnerOf(t *testing.T) {
	tests := []struct {
		name     string
		pod      corev1.Pod
		wantKind string
		wantName string
	}{
		{
			name: "ReplicaSet resolves to its Deployment via the pod-template-hash",
			pod: pod("default", "api-7d9f8b6c4d-x2k9l",
				withOwner("ReplicaSet", "api-7d9f8b6c4d", true),
				withPodTemplateHash("7d9f8b6c4d")),
			wantKind: "Deployment", wantName: "api",
		},
		{
			name: "Deployment name containing hyphens survives the strip",
			pod: pod("default", "my-cool-api-7d9f8b6c4d-x2k9l",
				withOwner("ReplicaSet", "my-cool-api-7d9f8b6c4d", true),
				withPodTemplateHash("7d9f8b6c4d")),
			wantKind: "Deployment", wantName: "my-cool-api",
		},
		{
			name: "missing pod-template-hash falls back to dropping the last segment",
			pod: pod("default", "api-7d9f8b6c4d-x2k9l",
				withOwner("ReplicaSet", "api-7d9f8b6c4d", true)),
			wantKind: "Deployment", wantName: "api",
		},
		{
			name:     "StatefulSet is reported as itself",
			pod:      pod("db", "pg-0", withOwner("StatefulSet", "pg", true)),
			wantKind: "StatefulSet", wantName: "pg",
		},
		{
			name:     "DaemonSet is reported as itself",
			pod:      pod("kube-system", "cilium-abcde", withOwner("DaemonSet", "cilium", true)),
			wantKind: "DaemonSet", wantName: "cilium",
		},
		{
			// Not "CronFoo": recovering a CronJob's name means stripping a timestamp,
			// and a wrong strip would attribute one workload's images to another.
			name:     "Job created by a CronJob is reported as the Job",
			pod:      pod("batch", "nightly-28401120-abcde", withOwner("Job", "nightly-28401120", true)),
			wantKind: "Job", wantName: "nightly-28401120",
		},
		{
			// Verified against a live Talos cluster: kubelet sets the Node as the
			// controller of static pods, and reporting that kind would merge
			// kube-apiserver, kube-scheduler and kube-controller-manager into one
			// workload named after the node.
			name: "static pod owned by a Node is its own Pod",
			pod: pod("kube-system", "kube-apiserver-node1",
				withOwner("Node", "node1", true)),
			wantKind: "Pod", wantName: "kube-apiserver-node1",
		},
		{
			name:     "bare pod owns itself",
			pod:      pod("kube-system", "etcd-node1"),
			wantKind: "Pod", wantName: "etcd-node1",
		},
		{
			name: "non-controller owner references are ignored",
			pod: pod("default", "orphan",
				withOwner("ReplicaSet", "not-the-controller", false)),
			wantKind: "Pod", wantName: "orphan",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			kind, name := ownerOf(&tc.pod)
			is.Equal(kind, tc.wantKind)
			is.Equal(name, tc.wantName)
		})
	}
}

func TestBuildSnapshotAggregatesPods(t *testing.T) {
	is := is.New(t)

	pods := []corev1.Pod{
		// Two pods of one Deployment on the same digest collapse to pod_count 2.
		pod("default", "api-abc-1",
			withOwner("ReplicaSet", "api-abc", true), withPodTemplateHash("abc"),
			withContainer("api", "ghcr.io/x/api:1", "ghcr.io/x/api@"+digestA)),
		pod("default", "api-abc-2",
			withOwner("ReplicaSet", "api-abc", true), withPodTemplateHash("abc"),
			withContainer("api", "ghcr.io/x/api:1", "ghcr.io/x/api@"+digestA)),
		// A third pod of the same Deployment mid-rollout on a different digest must
		// stay a separate row: collapsing by workload alone would hide half the
		// rollout, which is why the digest is part of the natural key.
		pod("default", "api-def-1",
			withOwner("ReplicaSet", "api-def", true), withPodTemplateHash("def"),
			withContainer("api", "ghcr.io/x/api:2", "ghcr.io/x/api@"+digestB)),
	}

	got := buildSnapshot(pods)
	is.Equal(len(got), 2)

	is.Equal(got[0].WorkloadKind, "Deployment")
	is.Equal(got[0].WorkloadName, "api")
	is.Equal(*got[0].ImageDigest, digestA)
	is.Equal(got[0].PodCount, int32(2))

	is.Equal(*got[1].ImageDigest, digestB)
	is.Equal(got[1].PodCount, int32(1))
	// Both rows belong to the same Deployment: the split is by digest, not by
	// ReplicaSet, so a rollout does not rename the workload.
	is.Equal(got[1].WorkloadName, "api")
}

func TestBuildSnapshotReportsUnresolvableRatherThanDropping(t *testing.T) {
	is := is.New(t)

	pods := []corev1.Pod{
		pod("default", "legacy", withOwner("StatefulSet", "legacy", true),
			withContainer("app", "nginx:1.25", "docker://"+digestA)),
	}

	got := buildSnapshot(pods)
	// Dropping the row would make the workload invisible, which reads as "nothing
	// is running there" — the one failure mode ADR-044 K5 forbids.
	is.Equal(len(got), 1)
	is.Equal(got[0].ImageDigest, nil)
	is.Equal(got[0].ImageRef, "nginx:1.25")
	is.Equal(countUnresolvable(got), 1)
}

func TestBuildSnapshotIncludesInitContainers(t *testing.T) {
	is := is.New(t)

	pods := []corev1.Pod{
		pod("default", "api-abc-1",
			withOwner("ReplicaSet", "api-abc", true), withPodTemplateHash("abc"),
			withInitContainer("migrate", "ghcr.io/x/api:1", "ghcr.io/x/api@"+digestB),
			withContainer("api", "ghcr.io/x/api:1", "ghcr.io/x/api@"+digestA)),
	}

	got := buildSnapshot(pods)
	is.Equal(len(got), 2)
	// Sorted by container name within the workload.
	is.Equal(got[0].ContainerName, "api")
	is.Equal(got[1].ContainerName, "migrate")
	is.Equal(*got[1].ImageDigest, digestB)
}

func TestBuildSnapshotExcludesNonRunningPods(t *testing.T) {
	is := is.New(t)

	pods := []corev1.Pod{
		pod("batch", "done", withOwner("Job", "done", true), withPhase(corev1.PodSucceeded),
			withContainer("job", "ghcr.io/x/job:1", "ghcr.io/x/job@"+digestA)),
		pod("batch", "failed", withOwner("Job", "failed", true), withPhase(corev1.PodFailed),
			withContainer("job", "ghcr.io/x/job:1", "ghcr.io/x/job@"+digestA)),
		pod("batch", "pending", withOwner("Job", "pending", true), withPhase(corev1.PodPending),
			withContainer("job", "ghcr.io/x/job:1", "")),
	}

	// The inventory is current state, not history: a Succeeded pod is running
	// nothing, and reporting it would make the snapshot a partial changelog.
	is.Equal(len(buildSnapshot(pods)), 0)
}

func TestBuildSnapshotFallsBackToSpecImageForDisplay(t *testing.T) {
	is := is.New(t)

	p := pod("default", "solo", withContainer("app", "ghcr.io/x/app:1", digestA))
	// A status that has resolved the digest but not the reference: image_ref is
	// required server-side, so the spec's image stands in for display.
	p.Status.ContainerStatuses[0].Image = ""

	got := buildSnapshot([]corev1.Pod{p})
	is.Equal(len(got), 1)
	is.Equal(got[0].ImageRef, "ghcr.io/x/app:1")
	is.Equal(*got[0].ImageDigest, digestA)
}

func TestBuildSnapshotIsDeterministic(t *testing.T) {
	is := is.New(t)

	pods := []corev1.Pod{
		pod("zeta", "z", withContainer("c", "img:1", digestA)),
		pod("alpha", "a", withContainer("b", "img:1", digestA)),
		pod("alpha", "a2", withContainer("a", "img:1", digestB)),
	}

	first := buildSnapshot(pods)
	second := buildSnapshot(pods)
	is.Equal(len(first), 3)
	// Map iteration order must not leak into the wire format, or two snapshots of
	// an unchanged cluster would not be comparable.
	for i := range first {
		is.Equal(first[i], second[i])
	}
	is.Equal(first[0].K8sNamespace, "alpha")
	is.Equal(first[0].WorkloadName, "a")
	is.Equal(first[2].K8sNamespace, "zeta")
}
