package api

// ---------------------------------------------------------------------------
// Clusters
// ---------------------------------------------------------------------------

// ClusterResponse is a registered Kubernetes cluster reporting its running
// workloads (ADR-044). Like a source, it carries no visibility of its own —
// the owning namespace decides who may see it.
type ClusterResponse struct {
	ID            string `json:"id"`
	NamespaceID   string `json:"namespace_id"`
	NamespaceName string `json:"namespace_name,omitempty" doc:"Owning namespace name; populated on list responses"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	LastSeenAt    string `json:"last_seen_at,omitempty" doc:"When an agent last pushed a snapshot. Empty means no agent has ever reported: a cluster showing no workloads for this reason is not a cluster running nothing."`
	AutoIngest    bool   `json:"auto_ingest" doc:"Submit a scan job for every running image with no SBOM whose host resolves to a registry in this cluster's namespace, on every accepted snapshot."`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ListClustersInput is the request for GET /api/v1/clusters.
type ListClustersInput struct {
	NamespaceID string `query:"namespace_id" doc:"Limit to clusters in one namespace"`
}

// ListMyClustersInput is the request for GET /api/v1/users/me/clusters.
type ListMyClustersInput struct{}

// ListClustersOutput is the response for GET /api/v1/clusters.
type ListClustersOutput struct {
	Body struct {
		Data []ClusterResponse `json:"data"`
	}
}

// GetClusterInput is the request for GET /api/v1/clusters/{id}.
type GetClusterInput struct {
	ID string `path:"id" doc:"Cluster UUID" format:"uuid"`
}

// GetClusterOutput is the response for GET /api/v1/clusters/{id}.
type GetClusterOutput struct {
	Body ClusterResponse
}

// CreateClusterInput is the request for POST /api/v1/clusters.
type CreateClusterInput struct {
	Body struct {
		NamespaceID string `json:"namespace_id" format:"uuid" doc:"Owning namespace UUID"`
		Name        string `json:"name" minLength:"1" maxLength:"100" doc:"Cluster name, unique within the namespace"`
		Description string `json:"description,omitempty" maxLength:"500"`
	}
}

// CreateClusterOutput is the response for POST /api/v1/clusters.
type CreateClusterOutput struct {
	Body ClusterResponse
}

// UpdateClusterInput is the request for PATCH /api/v1/clusters/{id}. The
// namespace is not settable: moving a cluster would silently change who can see
// every workload it has already reported.
type UpdateClusterInput struct {
	ID   string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Body struct {
		Name        string `json:"name" minLength:"1" maxLength:"100"`
		Description string `json:"description,omitempty" maxLength:"500"`
		// A pointer so omitting the field leaves the setting alone: a rename
		// must not be able to switch ingest off as a side effect.
		AutoIngest *bool `json:"auto_ingest,omitempty" doc:"Auto-ingest unknown running images on every accepted snapshot. Omit to leave unchanged."`
	}
}

// UpdateClusterOutput is the response for PATCH /api/v1/clusters/{id}.
type UpdateClusterOutput struct {
	Body ClusterResponse
}

// DeleteClusterInput is the request for DELETE /api/v1/clusters/{id}.
type DeleteClusterInput struct {
	ID string `path:"id" doc:"Cluster UUID" format:"uuid"`
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

// InventoryWorkload is one running container image in a pushed snapshot.
type InventoryWorkload struct {
	K8sNamespace  string `json:"k8s_namespace" minLength:"1" maxLength:"253" doc:"Kubernetes namespace the workload runs in"`
	WorkloadKind  string `json:"workload_kind" minLength:"1" maxLength:"63" doc:"Owning workload kind (Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod)"`
	WorkloadName  string `json:"workload_name" minLength:"1" maxLength:"253"`
	ContainerName string `json:"container_name" minLength:"1" maxLength:"253"`
	ImageRef      string `json:"image_ref" minLength:"1" maxLength:"2048" doc:"Image reference, for display only. Never used as an identity: a tag is mutable."`
	ImageDigest   string `json:"image_digest,omitempty" pattern:"^sha256:[0-9a-f]{64}$" doc:"Normalized digest from status.containerStatuses[].imageID. Omit when the agent could not extract one — that is reported as 'unresolvable', not silently dropped."`
	PodCount      int32  `json:"pod_count" minimum:"0" doc:"Running pods carrying this container at this digest"`
}

// PutInventoryInput is the request for POST /api/v1/clusters/{id}/inventory.
//
// The body is a COMPLETE snapshot, not a delta: anything the cluster is running
// and does not report here is treated as no longer running and is deleted
// (ADR-044 K7). An empty workloads array is therefore a meaningful, valid
// message — "this cluster is running nothing" — and not a no-op.
type PutInventoryInput struct {
	ID   string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Body struct {
		Workloads []InventoryWorkload `json:"workloads" doc:"The complete set of running container images. Omitted entries are pruned."`
	}
}

// PutInventoryOutput reports what the snapshot did, so an agent's logs can show
// drift rather than just success.
type PutInventoryOutput struct {
	Body struct {
		Accepted int    `json:"accepted" doc:"Workload rows in the snapshot"`
		Pruned   int    `json:"pruned" doc:"Rows deleted because the snapshot no longer reports them"`
		SeenAt   string `json:"seen_at" doc:"Timestamp recorded on the cluster"`
	}
}

// ClusterWorkloadResponse is one running workload joined to what OCIDex knows
// about its image.
type ClusterWorkloadResponse struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	K8sNamespace  string `json:"k8s_namespace"`
	WorkloadKind  string `json:"workload_kind"`
	WorkloadName  string `json:"workload_name"`
	ContainerName string `json:"container_name"`
	ImageRef      string `json:"image_ref"`
	ImageDigest   string `json:"image_digest,omitempty"`
	PodCount      int32  `json:"pod_count"`
	FirstSeenAt   string `json:"first_seen_at"`
	LastSeenAt    string `json:"last_seen_at"`

	// MatchState is always one of exact/index/unknown/unresolvable and is never
	// empty. Clients MUST branch on it: rendering an unmatched workload the same
	// as a matched one with no findings reports missing data as safety
	// (ADR-044 K5).
	MatchState string `json:"match_state" enum:"exact,index,unknown,unresolvable" doc:"exact = digest matched an SBOM; index = matched a multi-arch image index, so the exact platform is unknown; unknown = real digest with no ingested SBOM (coverage gap); unresolvable = no digest could be read from the container (agent/runtime gap)"`

	SBOMID         string `json:"sbom_id,omitempty"`
	ArtifactID     string `json:"artifact_id,omitempty"`
	ArtifactName   string `json:"artifact_name,omitempty"`
	ArtifactType   string `json:"artifact_type,omitempty"`
	SubjectVersion string `json:"subject_version,omitempty"`

	// Vulns is present only for a matched workload. Its absence means the image
	// was never assessed, which is a different fact from an assessed image with
	// no findings — omitting the object rather than sending zeros is what stops
	// a client from rendering the two identically (ADR-044 K5).
	Vulns *WorkloadVulnCounts `json:"vulns,omitempty" doc:"Findings in the matched SBOM. Absent when no SBOM matched — absence is not zero"`
}

// WorkloadVulnCounts is the per-severity finding count for a matched workload's
// SBOM, deduplicated by canonical id so an OSV alias group counts once.
type WorkloadVulnCounts struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
}

// WorkloadCoverageResponse accompanies every workload listing. It exists so a
// consumer cannot render a vulnerability count without also having the number
// of workloads that count silently excludes.
type WorkloadCoverageResponse struct {
	Total        int64 `json:"total"`
	Matched      int64 `json:"matched"`
	Unknown      int64 `json:"unknown" doc:"Valid digests with no ingested SBOM: a coverage gap"`
	Unresolvable int64 `json:"unresolvable" doc:"Containers whose imageID yielded no digest: an agent or runtime gap"`
	Pods         int64 `json:"pods" doc:"Running pods those workload-containers add up to. Reported beside total, not instead of it: total is the unit the match states partition"`
}

// ListClusterWorkloadsInput is the request for GET /api/v1/clusters/{id}/workloads.
type ListClusterWorkloadsInput struct {
	ID           string `path:"id" doc:"Cluster UUID" format:"uuid"`
	K8sNamespace string `query:"k8s_namespace" doc:"Filter to one Kubernetes namespace"`
	MatchState   string `query:"match_state" enum:"exact,index,unknown,unresolvable" doc:"Filter by SBOM match state"`
	Q            string `query:"q" doc:"Substring match over workload name, container name and image reference"`
	Sort         string `query:"sort" enum:"k8s_namespace,workload_name,container_name,image_ref,match_state,pod_count,last_seen_at,vuln_count" doc:"Column to sort by. vuln_count orders by severity, worst first, and sorts unmatched workloads last in either direction"`
	Dir          string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc)"`
	PaginationParams
}

// ListClusterWorkloadsOutput is the response for GET /api/v1/clusters/{id}/workloads.
//
// Coverage is part of the same response rather than a separate endpoint on
// purpose: a client that has to make a second call to learn what the first call
// omitted will eventually ship without making it.
type ListClusterWorkloadsOutput struct {
	Body struct {
		Data []ClusterWorkloadResponse `json:"data"`
		// Coverage counts the whole cluster and ignores the filters above.
		// Narrowing it to the filter would make the number mean something
		// different on every page, which is precisely what K5 forbids.
		Coverage   WorkloadCoverageResponse `json:"coverage"`
		Pagination PaginationMeta           `json:"pagination"`
	}
}

// ClusterImageResponse is one distinct image the cluster runs, with the
// workloads running it collapsed into counts.
//
// MatchState and Vulns carry exactly the meaning they carry on
// ClusterWorkloadResponse, including Vulns being absent rather than zero for an
// image that was never assessed (ADR-044 K5).
type ClusterImageResponse struct {
	ImageRef    string `json:"image_ref"`
	ImageDigest string `json:"image_digest,omitempty"`

	WorkloadCount  int64 `json:"workload_count" doc:"Workload-containers running this image"`
	PodCount       int64 `json:"pod_count" doc:"Running pods those workload-containers add up to"`
	NamespaceCount int64 `json:"namespace_count" doc:"Kubernetes namespaces the image appears in"`

	// One place the image runs, chosen deterministically. An example, not the
	// whole answer: the by-workload listing enumerates them all.
	SampleNamespace string `json:"sample_namespace,omitempty"`
	SampleWorkload  string `json:"sample_workload,omitempty"`

	LastSeenAt string `json:"last_seen_at"`

	MatchState string `json:"match_state" enum:"exact,index,unknown,unresolvable" doc:"exact = digest matched an SBOM; index = matched a multi-arch image index, so the exact platform is unknown; unknown = real digest with no ingested SBOM (coverage gap); unresolvable = no digest could be read from the container (agent/runtime gap)"`

	SBOMID         string `json:"sbom_id,omitempty"`
	ArtifactID     string `json:"artifact_id,omitempty"`
	ArtifactName   string `json:"artifact_name,omitempty"`
	ArtifactType   string `json:"artifact_type,omitempty"`
	SubjectVersion string `json:"subject_version,omitempty"`

	Vulns *WorkloadVulnCounts `json:"vulns,omitempty" doc:"Findings in the matched SBOM. Absent when no SBOM matched — absence is not zero"`
}

// ListClusterImagesInput is the request for GET /api/v1/clusters/{id}/images.
// It takes the same filters as the workload listing, so switching grouping in a
// client keeps whatever the reader had narrowed to.
type ListClusterImagesInput struct {
	ID           string `path:"id" doc:"Cluster UUID" format:"uuid"`
	K8sNamespace string `query:"k8s_namespace" doc:"Filter to one Kubernetes namespace"`
	MatchState   string `query:"match_state" enum:"exact,index,unknown,unresolvable" doc:"Filter by SBOM match state"`
	Q            string `query:"q" doc:"Substring match over workload name, container name and image reference"`
	Sort         string `query:"sort" enum:"image_ref,match_state,workload_count,pod_count,last_seen_at,vuln_count" doc:"Column to sort by. vuln_count orders by severity, worst first, and sorts unassessed images last in either direction"`
	Dir          string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc)"`
	PaginationParams
}

// ListClusterImagesOutput is the response for GET /api/v1/clusters/{id}/images.
//
// Coverage rides along for the same reason it rides along with the workload
// listing: a client must not be able to render finding counts without also
// holding the number of running containers those counts say nothing about.
type ListClusterImagesOutput struct {
	Body struct {
		Data       []ClusterImageResponse   `json:"data"`
		Coverage   WorkloadCoverageResponse `json:"coverage"`
		Pagination PaginationMeta           `json:"pagination"`
	}
}

// ListClusterNamespacesInput is the request for
// GET /api/v1/clusters/{id}/k8s-namespaces.
type ListClusterNamespacesInput struct {
	ID string `path:"id" doc:"Cluster UUID" format:"uuid"`
}

// NamespaceFacetResponse is one selectable value for the namespace filter.
type NamespaceFacetResponse struct {
	K8sNamespace  string `json:"k8s_namespace"`
	WorkloadCount int64  `json:"workload_count" doc:"Containers reported in this namespace"`
}

// ListClusterNamespacesOutput is the response for
// GET /api/v1/clusters/{id}/k8s-namespaces.
//
// The facets are served separately from the workload page because they describe
// the whole cluster: derived from a page of rows they would offer only the
// namespaces that page happens to contain.
type ListClusterNamespacesOutput struct {
	Body struct {
		Data []NamespaceFacetResponse `json:"data"`
	}
}

// ---------------------------------------------------------------------------
// Running vulnerabilities
// ---------------------------------------------------------------------------

// RunningVulnResponse is one vulnerability carried by an image currently
// running in a cluster.
type RunningVulnResponse struct {
	ID            string   `json:"id" doc:"Native advisory id of the representative record (OSV, GHSA, …)"`
	CanonicalID   string   `json:"canonical_id" doc:"The id this finding is keyed and linked by, normally a CVE. Aliased advisories are collapsed into one row."`
	Severity      string   `json:"severity,omitempty"`
	CvssScore     *float32 `json:"cvss_score,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	WorkloadCount int64    `json:"workload_count" doc:"Distinct running workloads affected in this cluster"`
}

// ListClusterVulnsInput is the request for GET /api/v1/clusters/{id}/vulns.
type ListClusterVulnsInput struct {
	ID       string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Severity string `query:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW" doc:"Filter by severity"`
	Sort     string `query:"sort" enum:"severity,cvss_score,workload_count,canonical_id" doc:"Column to sort by (default severity, worst first)"`
	Dir      string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc)"`
	PaginationParams
}

// ListClusterVulnsOutput is the response for GET /api/v1/clusters/{id}/vulns.
//
// Coverage rides along for the same reason it rides along with the workload
// listing, and here it matters more: these findings describe only the matched
// workloads. A client that renders the counts without the denominator is
// reporting missing data as safety (ADR-044 K5).
type ListClusterVulnsOutput struct {
	Body struct {
		Data       []RunningVulnResponse    `json:"data"`
		Coverage   WorkloadCoverageResponse `json:"coverage"`
		Pagination PaginationMeta           `json:"pagination"`
	}
}

// RunningWorkloadResponse is a workload carrying a vulnerability, named
// together with the cluster it runs in.
type RunningWorkloadResponse struct {
	ClusterWorkloadResponse
	ClusterName string `json:"cluster_name"`
}

// ListVulnWorkloadsInput is the request for GET /api/v1/vulns/{id}/workloads.
type ListVulnWorkloadsInput struct {
	ID        string `path:"id" doc:"Vulnerability id (CVE or GHSA); aliases of the same advisory resolve to the same workloads"`
	ClusterID string `query:"cluster_id" doc:"Limit to one cluster. Omitted, the answer spans every cluster the caller can see."`
	Limit     int32  `query:"limit" default:"50" minimum:"1" maximum:"200"`
}

// ListVulnWorkloadsOutput is the response for GET /api/v1/vulns/{id}/workloads.
type ListVulnWorkloadsOutput struct {
	Body struct {
		Data []RunningWorkloadResponse `json:"data"`
	}
}

// ListClusterUnknownImagesInput is the request for
// GET /api/v1/clusters/{id}/unknown-images.
type ListClusterUnknownImagesInput struct {
	ID string `path:"id" doc:"Cluster UUID" format:"uuid"`
	PaginationParams
}

// UnknownImageResponse is one image running in the cluster with no ingested
// SBOM, together with whether OCIDex could ingest it.
//
// The reason is reported rather than reduced to a boolean because the remedies
// differ: adding a registry, enabling one, and widening its repository patterns
// are three different actions, and a bare "cannot ingest" would send everyone
// to the first one.
type UnknownImageResponse struct {
	ImageRef           string  `json:"image_ref"`
	ImageDigest        string  `json:"image_digest"`
	RegistryHost       string  `json:"registry_host,omitempty" doc:"Host parsed out of image_ref; empty when the reference carries none"`
	Repository         string  `json:"repository,omitempty"`
	WorkloadCount      int64   `json:"workload_count" doc:"Containers running this image"`
	PodCount           int64   `json:"pod_count"`
	SampleK8sNamespace string  `json:"sample_k8s_namespace,omitempty"`
	SampleWorkloadName string  `json:"sample_workload_name,omitempty"`
	Reason             string  `json:"reason" enum:"ready,no_registry,registry_disabled,pattern_excluded,unparseable_ref" doc:"Why this image can or cannot be ingested"`
	RegistryID         *string `json:"registry_id,omitempty" doc:"Registry that serves this host, when one was matched at all"`
	RegistryName       *string `json:"registry_name,omitempty"`
}

// UnknownImageReasonCounts breaks the whole gap down by remedy.
//
// It counts the gap, not the page: a reader looking at twenty "no registry"
// rows out of four hundred needs to know whether adding that registry closes
// the gap or a twentieth of it (ADR-044 K5).
type UnknownImageReasonCounts struct {
	Ready            int64 `json:"ready" doc:"A registry in the namespace serves the image and accepts its repository"`
	NoRegistry       int64 `json:"no_registry" doc:"No registry in the namespace is configured for the image's host"`
	RegistryDisabled int64 `json:"registry_disabled" doc:"The host matches a registry that is switched off"`
	PatternExcluded  int64 `json:"pattern_excluded" doc:"The registry's repository patterns exclude this repository"`
	UnparseableRef   int64 `json:"unparseable_ref" doc:"The reported reference carries no host to resolve against"`
}

// ListClusterUnknownImagesOutput is the response for
// GET /api/v1/clusters/{id}/unknown-images.
type ListClusterUnknownImagesOutput struct {
	Body struct {
		Data       []UnknownImageResponse   `json:"data"`
		Reasons    UnknownImageReasonCounts `json:"reasons" doc:"Breakdown of the entire gap by remedy, independent of the page returned"`
		Pagination PaginationMeta           `json:"pagination"`
	}
}

// IngestUnknownInput is the request for POST /api/v1/clusters/{id}/ingest-unknown.
type IngestUnknownInput struct {
	ID   string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Body struct {
		// Naming digests is what lets a per-image button mean one image. An
		// empty list is the whole gap, which is what the bulk button and the
		// snapshot trigger both want.
		ImageDigests []string `json:"image_digests,omitempty" doc:"Limit the run to these running image digests. Omit to ingest every unknown image the cluster reports."`
	}
}

// IngestUnknownOutput reports what an ingest run did with every unknown image
// it considered.
//
// The skips are broken out by reason rather than summed. A single "skipped"
// number cannot be acted on: adding a registry, enabling one, widening its
// repository patterns, and fixing a node runtime are four different jobs.
type IngestUnknownOutput struct {
	Body struct {
		Considered              int `json:"considered" doc:"Unknown images looked at; the counts below account for all of them"`
		Queued                  int `json:"queued" doc:"Scan jobs enqueued. A multi-arch image expands into one job per platform, so this can exceed the image count."`
		SkippedNoRegistry       int `json:"skipped_no_registry" doc:"No registry in this cluster's namespace is configured for the image's host"`
		SkippedRegistryDisabled int `json:"skipped_registry_disabled" doc:"The host matches a registry that is switched off"`
		SkippedPatternExcluded  int `json:"skipped_pattern_excluded" doc:"The registry's repository patterns exclude this repository"`
		SkippedUnparseableRef   int `json:"skipped_unparseable_ref" doc:"The reported reference carries no host to resolve against"`
		Failed                  int `json:"failed" doc:"Submission errored against a reachable registry — transient, unlike the skips"`
	}
}
