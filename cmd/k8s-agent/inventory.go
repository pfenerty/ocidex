package main

import (
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/pfenerty/ocidex/pkg/client"
)

// digestRe matches a canonical sha256 digest. It is deliberately the same
// expression as the cluster_workload_digest_form CHECK constraint in migration
// 00059 and the pattern on the API's InventoryWorkload.image_digest: anything
// the agent reports must already satisfy the constraint it will be stored under,
// so a malformed digest is caught here rather than as a 422 or a failed INSERT.
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// normalizeImageID extracts the registry-addressable digest from a kubelet
// imageID, implementing the ADR-044 K3 table:
//
//	docker.io/library/nginx@sha256:abc…   containerd            → sha256:abc…
//	sha256:abc…                           CRI-O / old kubelets  → sha256:abc…
//	docker-pullable://nginx@sha256:abc…   dockershim            → sha256:abc…
//	docker://sha256:abc…                  dockershim image ID   → unresolvable
//
// The last row is the one that matters. `docker://sha256:…` carries the *local
// image config ID*, which is not addressable in any registry and can never equal
// an sbom.digest. Returning it as a digest would produce a row that is
// permanently "unknown" — indistinguishable from a genuine coverage gap, and
// pointing the operator at ingesting an SBOM that would not help. Reporting it
// as unresolvable instead names the real problem: the node runtime.
//
// The general rule that yields that behaviour is "a scheme with no @ is a local
// image ID", which also covers any future runtime that reports the same shape.
func normalizeImageID(imageID string) (string, bool) {
	id := strings.TrimSpace(imageID)
	if id == "" {
		return "", false
	}

	hadScheme := false
	if i := strings.Index(id, "://"); i >= 0 {
		hadScheme = true
		id = id[i+3:]
	}

	if at := strings.LastIndex(id, "@"); at >= 0 {
		id = id[at+1:]
	} else if hadScheme {
		return "", false
	}

	// Digests are canonically lower-case; fold rather than reject, since an
	// upper-case variant is a formatting difference and not a missing digest.
	id = strings.ToLower(id)
	if !digestRe.MatchString(id) {
		return "", false
	}
	return id, true
}

// workloadKey is the natural key migration 00059 stores under: the owning
// workload, the container within it, and the digest. Digest is part of the key
// because during a rolling update two pods of one Deployment legitimately run
// different digests, and collapsing them would hide exactly half of the rollout.
type workloadKey struct {
	namespace string
	kind      string
	name      string
	container string
	digest    string
}

// ownerOf resolves the workload a pod belongs to using only the pod itself, so
// the agent's RBAC stays at pod read access.
//
// A pod's controller reference points at the *intermediate* object — a
// Deployment's pods are owned by a ReplicaSet, a CronJob's by a Job. Walking one
// more hop would require read access to replicasets and jobs, so the ReplicaSet
// case is instead resolved by name: the ReplicaSet is always named
// `<deployment>-<pod-template-hash>`, and the hash is on the pod as a label, so
// stripping it is exact rather than a guess.
//
// Jobs are reported as Jobs even when a CronJob created them. The CronJob's name
// is only recoverable by heuristically stripping a timestamp suffix, and a wrong
// guess would silently attribute one workload's images to another; a Job is a
// true statement about what is running.
func ownerOf(pod *corev1.Pod) (kind, name string) {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		switch ref.Kind {
		case "ReplicaSet":
			return "Deployment", stripPodTemplateHash(ref.Name, pod.Labels["pod-template-hash"])
		case "Node":
			// A static pod is owned by the Node that runs it. Reporting kind "Node"
			// would name the *machine* as the workload, collapsing every control-plane
			// component on a node into one row whose name is the node's — so
			// kube-apiserver and kube-scheduler would appear to be one workload.
			// A static pod is its own workload, and "Pod" is one of the kinds ADR-044
			// enumerates; "Node" is not.
			return "Pod", pod.Name
		default:
			return ref.Kind, ref.Name
		}
	}
	// A bare pod is its own workload — static pods on control-plane nodes are the
	// common case, and they are exactly the images an operator most wants to see.
	return "Pod", pod.Name
}

func stripPodTemplateHash(rsName, hash string) string {
	if hash != "" {
		if trimmed := strings.TrimSuffix(rsName, "-"+hash); trimmed != "" && trimmed != rsName {
			return trimmed
		}
	}
	// No usable label: fall back to dropping the trailing segment, which is what
	// the ReplicaSet name always ends in. Returning the ReplicaSet name unchanged
	// would be worse than an approximate Deployment name only if it were wrong —
	// but it splits a Deployment's history across every rollout, so prefer the
	// strip and keep the unstripped name only when there is nothing to strip.
	if i := strings.LastIndex(rsName, "-"); i > 0 {
		return rsName[:i]
	}
	return rsName
}

// containerStatuses flattens a pod's regular, init and ephemeral container
// statuses. All three are reported (ADR-044 K3): an init container's image runs
// in the cluster and can carry vulnerabilities just as a long-lived one can.
func containerStatuses(pod *corev1.Pod) []corev1.ContainerStatus {
	out := make([]corev1.ContainerStatus, 0,
		len(pod.Status.ContainerStatuses)+len(pod.Status.InitContainerStatuses)+len(pod.Status.EphemeralContainerStatuses))
	out = append(out, pod.Status.ContainerStatuses...)
	out = append(out, pod.Status.InitContainerStatuses...)
	out = append(out, pod.Status.EphemeralContainerStatuses...)
	return out
}

// specImages maps container name to the image from the pod spec, used only as a
// display fallback when the status has not recorded a resolved reference yet.
func specImages(pod *corev1.Pod) map[string]string {
	m := make(map[string]string, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		m[c.Name] = c.Image
	}
	for _, c := range pod.Spec.InitContainers {
		m[c.Name] = c.Image
	}
	for _, c := range pod.Spec.EphemeralContainers {
		m[c.Name] = c.Image
	}
	return m
}

// bareIDRe matches a value that identifies an image without naming it: a
// digest-shaped string with no repository in front of it.
var bareIDRe = regexp.MustCompile(`^(sha256:)?[0-9a-fA-F]{64}$`)

// displayRef picks the reference a human should see for a container.
//
// The obvious source is containerStatuses[].image, and usually it is
// `repo:tag`. But containerd frequently reports the local image ID there
// instead — a bare `sha256:…` — and the pod spec is the only place the
// authored name survives. Preferring the spec whenever the status is a bare
// identifier is what keeps rows from rendering as 71 characters of hex.
//
// The reverse preference would be wrong: when the status *does* carry a name it
// is the resolved one, which can differ from the spec's after a mutating
// webhook or an image policy rewrite, and the resolved name is what actually
// ran.
func displayRef(statusImage, specImage string) string {
	status := strings.TrimSpace(statusImage)
	if status != "" && !bareIDRe.MatchString(status) {
		return status
	}
	if spec := strings.TrimSpace(specImage); spec != "" {
		return spec
	}
	// Nothing better exists. The bare id is still returned rather than dropped:
	// it is a real running container, and the row's digest is what OCIDex
	// matches on. The UI is responsible for not printing it as if it were a
	// name.
	return status
}

// buildSnapshot aggregates pods into the inventory rows to report. The result is
// sorted, so a snapshot is a deterministic function of cluster state — which is
// what makes a diff of two consecutive pushes readable.
//
// Pods not in the Running phase are excluded: Succeeded and Failed pods are not
// running anything, and reporting them would make the inventory a partial
// history, which migration 00059 explicitly declines to be.
func buildSnapshot(pods []corev1.Pod) []client.InventoryWorkload {
	type agg struct {
		imageRef string
		pods     int32
	}
	acc := map[workloadKey]*agg{}

	for i := range pods {
		pod := &pods[i]
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		kind, name := ownerOf(pod)
		spec := specImages(pod)

		for _, cs := range containerStatuses(pod) {
			digest, _ := normalizeImageID(cs.ImageID)

			ref := displayRef(cs.Image, spec[cs.Name])
			if ref == "" {
				// image_ref is required with minLength 1 server-side, and a
				// container with no image in either status or spec cannot exist in
				// an admitted pod. Skip rather than invent a placeholder that would
				// read like a real image reference.
				continue
			}

			key := workloadKey{
				namespace: pod.Namespace,
				kind:      kind,
				name:      name,
				container: cs.Name,
				digest:    digest,
			}
			if a, ok := acc[key]; ok {
				a.pods++
				continue
			}
			acc[key] = &agg{imageRef: ref, pods: 1}
		}
	}

	out := make([]client.InventoryWorkload, 0, len(acc))
	for key, a := range acc {
		w := client.InventoryWorkload{
			K8sNamespace:  key.namespace,
			WorkloadKind:  key.kind,
			WorkloadName:  key.name,
			ContainerName: key.container,
			ImageRef:      a.imageRef,
			PodCount:      a.pods,
		}
		// Left nil when normalization failed, which the server stores as NULL and
		// reports as "unresolvable" — a distinct state from a digest that matched
		// nothing (ADR-044 K5).
		if key.digest != "" {
			d := key.digest
			w.ImageDigest = &d
		}
		out = append(out, w)
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.K8sNamespace != b.K8sNamespace {
			return a.K8sNamespace < b.K8sNamespace
		}
		if a.WorkloadName != b.WorkloadName {
			return a.WorkloadName < b.WorkloadName
		}
		if a.ContainerName != b.ContainerName {
			return a.ContainerName < b.ContainerName
		}
		return derefOr(a.ImageDigest, "") < derefOr(b.ImageDigest, "")
	})
	return out
}

func derefOr(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return *s
}

// countUnresolvable reports how many rows carry no digest. Logged on every push
// so an agent that has silently stopped resolving digests — a node runtime
// change, say — shows up in the agent's own logs and not only as a coverage gap
// in the UI (ADR-044 K5).
func countUnresolvable(workloads []client.InventoryWorkload) int {
	n := 0
	for _, w := range workloads {
		if w.ImageDigest == nil {
			n++
		}
	}
	return n
}
