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
}

// WorkloadCoverageResponse accompanies every workload listing. It exists so a
// consumer cannot render a vulnerability count without also having the number
// of workloads that count silently excludes.
type WorkloadCoverageResponse struct {
	Total        int64 `json:"total"`
	Matched      int64 `json:"matched"`
	Unknown      int64 `json:"unknown" doc:"Valid digests with no ingested SBOM: a coverage gap"`
	Unresolvable int64 `json:"unresolvable" doc:"Containers whose imageID yielded no digest: an agent or runtime gap"`
}

// ListClusterWorkloadsInput is the request for GET /api/v1/clusters/{id}/workloads.
type ListClusterWorkloadsInput struct {
	ID string `path:"id" doc:"Cluster UUID" format:"uuid"`
}

// ListClusterWorkloadsOutput is the response for GET /api/v1/clusters/{id}/workloads.
//
// Coverage is part of the same response rather than a separate endpoint on
// purpose: a client that has to make a second call to learn what the first call
// omitted will eventually ship without making it.
type ListClusterWorkloadsOutput struct {
	Body struct {
		Data     []ClusterWorkloadResponse `json:"data"`
		Coverage WorkloadCoverageResponse  `json:"coverage"`
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
