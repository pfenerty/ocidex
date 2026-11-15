package api

// ---------------------------------------------------------------------------
// Clusters
// ---------------------------------------------------------------------------

// ClusterResponse is a registered Kubernetes cluster reporting its running
// workloads (ADR-044). Like a source, it carries no visibility of its own —
// the owning namespace decides who may see it.
type ClusterResponse struct {
	ID            string                  `json:"id"`
	NamespaceID   string                  `json:"namespaceId"`
	NamespaceName string                  `json:"namespaceName,omitempty" doc:"Owning namespace name; populated on list responses"`
	Name          string                  `json:"name"`
	Description   string                  `json:"description,omitempty"`
	LastSeenAt    string                  `json:"lastSeenAt,omitempty" doc:"When an agent last pushed a snapshot. Empty means no agent has ever reported: a cluster showing no workloads for this reason is not a cluster running nothing."`
	AutoIngest    bool                    `json:"autoIngest" doc:"Submit a scan job for every running image with no SBOM whose host resolves to a registry in this cluster's namespace, on every accepted snapshot."`
	Agent         *ClusterAgentResponse   `json:"agent,omitempty" doc:"What the agent reported about itself with its last accepted snapshot. Absent until an agent that self-reports has pushed."`
	Health        ClusterHealthResponse   `json:"health" doc:"The agent's health, derived from its pushes"`
	PausedAt      string                  `json:"pausedAt,omitempty" doc:"When the cluster was paused; empty while active"`
	Summary       *ClusterSummaryResponse `json:"summary,omitempty" doc:"Coverage and running criticals, on list responses for a cluster that has reported"`
	CreatedAt     string                  `json:"createdAt"`
	UpdatedAt     string                  `json:"updatedAt"`
}

// ClusterSummaryResponse is what the cluster list shows per row
// (ocidex-70eo.7): how much of what runs OCIDex can assess, and the worst of
// what it found. Criticals count only the matched containers, which is why
// coverage travels with them.
type ClusterSummaryResponse struct {
	Coverage         WorkloadCoverageResponse `json:"coverage"`
	RunningCriticals int64                    `json:"runningCriticals" doc:"Distinct critical vulnerabilities in matched running images"`
}

// ClusterHealthResponse is a cluster's derived agent health (ocidex-70eo.4).
type ClusterHealthResponse struct {
	State             string `json:"state" enum:"never_reported,healthy,stale,erroring,paused" doc:"never_reported: nothing pushed yet. healthy: last push accepted and recent. stale: no accepted push within three report intervals. erroring: the agent is pushing and being refused. paused: paused on purpose; snapshots are refused."`
	Reason            string `json:"reason,omitempty" doc:"Why, for every state but healthy"`
	StaleAfterSeconds int64  `json:"staleAfterSeconds,omitempty" doc:"Seconds after the last accepted push at which the cluster turns stale; absent for a one-shot agent"`
}

// ClusterPushResponse is one recorded push attempt.
type ClusterPushResponse struct {
	At           string `json:"at"`
	Accepted     bool   `json:"accepted"`
	Status       int    `json:"status" doc:"HTTP status the push received"`
	Reason       string `json:"reason,omitempty" doc:"Why it was refused"`
	Workloads    *int32 `json:"workloads,omitempty" doc:"Workload rows in an accepted snapshot"`
	AgentVersion string `json:"agentVersion,omitempty"`
}

// ListClusterPushesInput is the request for GET /api/v1/clusters/{id}/pushes.
type ListClusterPushesInput struct {
	ID    string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Limit int32  `query:"limit" minimum:"1" maximum:"50" default:"20"`
}

// ListClusterPushesOutput is the response for GET /api/v1/clusters/{id}/pushes.
type ListClusterPushesOutput struct {
	Body struct {
		Data []ClusterPushResponse `json:"data"`
	}
}

// ClusterAgentResponse is the agent's self-description as stored on the
// cluster, plus the server's verdict on its version.
type ClusterAgentResponse struct {
	Version               string   `json:"version,omitempty" doc:"Agent build version"`
	KubernetesVersion     string   `json:"kubernetesVersion,omitempty" doc:"Kubernetes server version (gitVersion)"`
	NodeCount             *int32   `json:"nodeCount,omitempty" doc:"Distinct nodes running the reported pods"`
	Namespaces            []string `json:"namespaces,omitempty" doc:"Namespace allowlist; empty or absent with reportIntervalSeconds set means every namespace"`
	ReportIntervalSeconds *int32   `json:"reportIntervalSeconds,omitempty" doc:"Seconds between snapshots; 0 for a one-shot agent"`
	PodName               string   `json:"podName,omitempty" doc:"The agent's own pod"`
	PodNamespace          string   `json:"podNamespace,omitempty" doc:"Namespace the agent runs in"`
	VersionSkew           string   `json:"versionSkew,omitempty" doc:"Set when the agent's major.minor differs from the server's"`
}

// ListClustersInput is the request for GET /api/v1/clusters.
type ListClustersInput struct {
	NamespaceID string `query:"namespaceId" doc:"Limit to clusters in one namespace"`
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
		NamespaceID string `json:"namespaceId" format:"uuid" doc:"Owning namespace UUID"`
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
		AutoIngest *bool `json:"autoIngest,omitempty" doc:"Auto-ingest unknown running images on every accepted snapshot. Omit to leave unchanged."`
		// Same pointer reasoning as AutoIngest.
		Paused *bool `json:"paused,omitempty" doc:"Pause (true) or resume (false) the cluster. A paused cluster refuses snapshots and keeps its last inventory. Omit to leave unchanged."`
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
	K8sNamespace  string `json:"k8sNamespace" minLength:"1" maxLength:"253" doc:"Kubernetes namespace the workload runs in"`
	WorkloadKind  string `json:"workloadKind" minLength:"1" maxLength:"63" doc:"Owning workload kind (Deployment, StatefulSet, DaemonSet, Job, CronJob, Pod)"`
	WorkloadName  string `json:"workloadName" minLength:"1" maxLength:"253"`
	ContainerName string `json:"containerName" minLength:"1" maxLength:"253"`
	ImageRef      string `json:"imageRef" minLength:"1" maxLength:"2048" doc:"Image reference, for display only. Never used as an identity: a tag is mutable."`
	ImageDigest   string `json:"imageDigest,omitempty" pattern:"^sha256:[0-9a-f]{64}$" doc:"Normalized digest from status.containerStatuses[].imageID. Omit when the agent could not extract one — that is reported as 'unresolvable', not silently dropped."`
	PodCount      int32  `json:"podCount" minimum:"0" doc:"Running pods carrying this container at this digest"`
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
		Agent     *InventoryAgent     `json:"agent,omitempty" doc:"The agent's description of itself. Optional, so an older agent's push is still accepted."`
	}
}

// InventoryAgent is what an agent reports about itself and its cluster with a
// snapshot (ocidex-70eo.3). Every field is optional.
type InventoryAgent struct {
	Version               string   `json:"version,omitempty" maxLength:"128" doc:"Agent build version"`
	KubernetesVersion     string   `json:"kubernetesVersion,omitempty" maxLength:"128" doc:"Kubernetes server gitVersion from the discovery API"`
	NodeCount             *int32   `json:"nodeCount,omitempty" minimum:"0" doc:"Distinct nodes running the reported pods"`
	Namespaces            []string `json:"namespaces,omitempty" maxItems:"1000" doc:"Namespace allowlist; empty means every namespace"`
	ReportIntervalSeconds *int32   `json:"reportIntervalSeconds,omitempty" minimum:"0" doc:"Seconds between snapshots; 0 for a one-shot agent"`
	PodName               string   `json:"podName,omitempty" maxLength:"253" doc:"The agent's own pod name"`
	PodNamespace          string   `json:"podNamespace,omitempty" maxLength:"253" doc:"Namespace the agent runs in"`
}

// PutInventoryOutput reports what the snapshot did, so an agent's logs can show
// drift rather than just success.
type PutInventoryOutput struct {
	Body struct {
		Accepted int    `json:"accepted" doc:"Workload rows in the snapshot"`
		Pruned   int    `json:"pruned" doc:"Rows deleted because the snapshot no longer reports them"`
		SeenAt   string `json:"seenAt" doc:"Timestamp recorded on the cluster"`
		// The agent logs these: a skew warning on the server's side alone would
		// reach nobody watching the agent.
		ServerVersion string `json:"serverVersion,omitempty" doc:"The server's version"`
		VersionSkew   string `json:"versionSkew,omitempty" doc:"Set when the reported agent version's major.minor differs from the server's"`
	}
}

// ClusterWorkloadResponse is one running workload joined to what OCIDex knows
// about its image.
type ClusterWorkloadResponse struct {
	ID            string `json:"id"`
	ClusterID     string `json:"clusterId"`
	K8sNamespace  string `json:"k8sNamespace"`
	WorkloadKind  string `json:"workloadKind"`
	WorkloadName  string `json:"workloadName"`
	ContainerName string `json:"containerName"`
	ImageRef      string `json:"imageRef"`
	ImageDigest   string `json:"imageDigest,omitempty"`
	PodCount      int32  `json:"podCount"`
	FirstSeenAt   string `json:"firstSeenAt"`
	LastSeenAt    string `json:"lastSeenAt"`

	// MatchState is always one of exact/index/unknown/unresolvable and is never
	// empty. Clients MUST branch on it: rendering an unmatched workload the same
	// as a matched one with no findings reports missing data as safety
	// (ADR-044 K5).
	MatchState string `json:"matchState" enum:"exact,index,unknown,unresolvable" doc:"exact = digest matched an SBOM; index = matched a multi-arch image index, so the exact platform is unknown; unknown = real digest with no ingested SBOM (coverage gap); unresolvable = no digest could be read from the container (agent/runtime gap)"`

	SBOMID         string `json:"sbomId,omitempty"`
	ArtifactID     string `json:"artifactId,omitempty"`
	ArtifactName   string `json:"artifactName,omitempty"`
	ArtifactType   string `json:"artifactType,omitempty"`
	SubjectVersion string `json:"subjectVersion,omitempty"`

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
	K8sNamespace string `query:"k8sNamespace" doc:"Filter to one Kubernetes namespace"`
	MatchState   string `query:"matchState" enum:"exact,index,unknown,unresolvable" doc:"Filter by SBOM match state"`
	Q            string `query:"q" doc:"Substring match over workload name, container name and image reference"`
	Sort         string `query:"sort" enum:"k8sNamespace,workloadName,containerName,imageRef,matchState,podCount,lastSeenAt,vulnCount" doc:"Column to sort by. vulnCount orders by severity, worst first, and sorts unmatched workloads last in either direction. Unset means namespace, then workload, then container."`
	Dir          string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc). Applies to sort only — with sort unset the default ordering ignores it."`
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
	ImageRef    string `json:"imageRef"`
	ImageDigest string `json:"imageDigest,omitempty"`

	WorkloadCount  int64 `json:"workloadCount" doc:"Workload-containers running this image"`
	PodCount       int64 `json:"podCount" doc:"Running pods those workload-containers add up to"`
	NamespaceCount int64 `json:"namespaceCount" doc:"Kubernetes namespaces the image appears in"`

	// One place the image runs, chosen deterministically. An example, not the
	// whole answer: the by-workload listing enumerates them all.
	SampleNamespace string `json:"sampleNamespace,omitempty"`
	SampleWorkload  string `json:"sampleWorkload,omitempty"`

	LastSeenAt string `json:"lastSeenAt"`

	MatchState string `json:"matchState" enum:"exact,index,unknown,unresolvable" doc:"exact = digest matched an SBOM; index = matched a multi-arch image index, so the exact platform is unknown; unknown = real digest with no ingested SBOM (coverage gap); unresolvable = no digest could be read from the container (agent/runtime gap)"`

	SBOMID         string `json:"sbomId,omitempty"`
	ArtifactID     string `json:"artifactId,omitempty"`
	ArtifactName   string `json:"artifactName,omitempty"`
	ArtifactType   string `json:"artifactType,omitempty"`
	SubjectVersion string `json:"subjectVersion,omitempty"`

	Vulns *WorkloadVulnCounts `json:"vulns,omitempty" doc:"Findings in the matched SBOM. Absent when no SBOM matched — absence is not zero"`
}

// ListClusterImagesInput is the request for GET /api/v1/clusters/{id}/images.
// It takes the same filters as the workload listing, so switching grouping in a
// client keeps whatever the reader had narrowed to.
type ListClusterImagesInput struct {
	ID           string `path:"id" doc:"Cluster UUID" format:"uuid"`
	K8sNamespace string `query:"k8sNamespace" doc:"Filter to one Kubernetes namespace"`
	MatchState   string `query:"matchState" enum:"exact,index,unknown,unresolvable" doc:"Filter by SBOM match state"`
	Q            string `query:"q" doc:"Substring match over workload name, container name and image reference"`
	Sort         string `query:"sort" enum:"imageRef,matchState,workloadCount,podCount,lastSeenAt,vulnCount" doc:"Column to sort by. vulnCount orders by severity, worst first, and sorts unassessed images last in either direction. Unset means image reference order."`
	Dir          string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc). Applies to sort only — with sort unset the default ordering ignores it."`
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
	K8sNamespace  string `json:"k8sNamespace"`
	WorkloadCount int64  `json:"workloadCount" doc:"Containers reported in this namespace"`
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
	CanonicalID   string   `json:"canonicalId" doc:"The id this finding is keyed and linked by, normally a CVE. Aliased advisories are collapsed into one row."`
	Severity      string   `json:"severity,omitempty"`
	CvssScore     *float32 `json:"cvssScore,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	WorkloadCount int64    `json:"workloadCount" doc:"Distinct running workloads affected in this cluster"`
}

// ListClusterVulnsInput is the request for GET /api/v1/clusters/{id}/vulns.
type ListClusterVulnsInput struct {
	ID       string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Severity string `query:"severity" enum:"CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN" doc:"Filter by severity"`
	Sort     string `query:"sort" enum:"severity,cvssScore,workloadCount,canonicalId" doc:"Column to sort by. Unset means worst first: severity, then CVSS."`
	Dir      string `query:"dir" enum:"asc,desc" doc:"Sort direction (default asc). Applies to sort only — with sort unset the worst-first default ordering ignores it."`
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
	ClusterName string `json:"clusterName"`
}

// ListVulnWorkloadsInput is the request for GET /api/v1/vulns/{id}/workloads.
type ListVulnWorkloadsInput struct {
	ID        string `path:"id" doc:"Vulnerability id (CVE or GHSA); aliases of the same advisory resolve to the same workloads"`
	ClusterID string `query:"clusterId" doc:"Limit to one cluster. Omitted, the answer spans every cluster the caller can see."`
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
// differ: adding credentials, enabling a registry, and fixing a node runtime
// are different actions, and a bare "cannot ingest" would send everyone to the
// first one.
type UnknownImageResponse struct {
	ImageRef           string  `json:"imageRef"`
	ImageDigest        string  `json:"imageDigest"`
	RegistryHost       string  `json:"registryHost,omitempty" doc:"Host parsed out of imageRef; empty when the reference carries none"`
	Repository         string  `json:"repository,omitempty"`
	WorkloadCount      int64   `json:"workloadCount" doc:"Containers running this image"`
	PodCount           int64   `json:"podCount"`
	SampleK8sNamespace string  `json:"sampleK8sNamespace,omitempty"`
	SampleWorkloadName string  `json:"sampleWorkloadName,omitempty"`
	Reason             string  `json:"reason" enum:"ready,scanning,unauthorized,egress_denied,failed,deleted,registry_disabled,unparseable_ref" doc:"Where this image stands: ready to queue, already has a job, or why it cannot be ingested (ADR-0044 K10)"`
	RegistryID         *string `json:"registryId,omitempty" doc:"Registry whose credentials pull this image, or the disabled one blocking it; absent on a ready image means an anonymous pull"`
	RegistryName       *string `json:"registryName,omitempty"`
}

// UnknownImageReasonCounts breaks the whole gap down by remedy.
//
// It counts the gap, not the page: a reader looking at twenty "no registry"
// rows out of four hundred needs to know whether adding that registry closes
// the gap or a twentieth of it (ADR-044 K5).
type UnknownImageReasonCounts struct {
	Ready            int64 `json:"ready" doc:"Will be queued next run, with a registry's credentials or anonymously"`
	Scanning         int64 `json:"scanning" doc:"A scan job is queued or running"`
	Unauthorized     int64 `json:"unauthorized" doc:"The host refused the pull; a registry with credentials for it is the remedy"`
	EgressDenied     int64 `json:"egressDenied" doc:"The host is in an address range the egress policy refuses"`
	Failed           int64 `json:"failed" doc:"The manifest was not there, or the scan used up its attempts; ingesting the row retries it"`
	Deleted          int64 `json:"deleted" doc:"Its SBOM was deleted on purpose; cluster ingest does not bring it back"`
	RegistryDisabled int64 `json:"registryDisabled" doc:"The host matches a registry that is switched off"`
	UnparseableRef   int64 `json:"unparseableRef" doc:"The reported reference carries no host to resolve against"`
}

// UnknownHostResponse is one registry the gap points at, rolled up.
//
// The gap is a list of images, but the remedy is a registry: one registry
// closes every row behind it. Reported per registry so the client can offer
// that as one action rather than repeating the same link on every row.
//
// The group is the scope, not the host. On a multi-tenant host the credentials
// stop working below the hostname, so ghcr.io/orgA and ghcr.io/orgB are two
// groups; host stays the registry address both would be configured with.
//
// Like the reason counts, this covers the entire gap and not the page.
type UnknownHostResponse struct {
	Host            string   `json:"host" doc:"Normalized registry host the images in this group name, and the address a registry for it would use"`
	Scope           string   `json:"scope" doc:"The group: the host plus any leading repository segments that belong to the registry rather than the image, e.g. ghcr.io/pfenerty"`
	Reason          string   `json:"reason" enum:"unauthorized,registry_disabled" doc:"The worst remedy seen for this group: a registry to add or fix credentials for, or one to switch on. Other states name no registry to configure and are not grouped here"`
	ImageCount      int64    `json:"imageCount"`
	PodCount        int64    `json:"podCount"`
	WorkloadCount   int64    `json:"workloadCount"`
	Repositories    []string `json:"repositories" doc:"Distinct repositories a registry would have to cover to close this group's gap, sorted; capped, so compare against repository_count"`
	RepositoryCount int64    `json:"repositoryCount" doc:"Distinct repository total, which may exceed the length of repositories"`
	RegistryID      *string  `json:"registryId,omitempty" doc:"Registry that serves this group, when one was matched at all"`
	RegistryName    *string  `json:"registryName,omitempty"`
}

// ListClusterUnknownImagesOutput is the response for
// GET /api/v1/clusters/{id}/unknown-images.
type ListClusterUnknownImagesOutput struct {
	Body struct {
		Data       []UnknownImageResponse   `json:"data"`
		Reasons    UnknownImageReasonCounts `json:"reasons" doc:"Breakdown of the entire gap by remedy, independent of the page returned"`
		Hosts      []UnknownHostResponse    `json:"hosts" doc:"The entire gap grouped by registry scope, biggest first; independent of the page returned"`
		Pagination PaginationMeta           `json:"pagination"`
		// ocidex-70eo.12: without a scanner, "ready" means "would be ready",
		// and the ingest endpoint answers 503. Clients branch on this rather
		// than offering an action that cannot run.
		ScanningEnabled bool `json:"scanningEnabled" doc:"Whether this deployment can scan images at all. When false, nothing can be ingested from here (manually or by auto-ingest) and the ingest endpoint returns 503."`
	}
}

// IngestUnknownInput is the request for POST /api/v1/clusters/{id}/ingest-unknown.
type IngestUnknownInput struct {
	ID   string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Body struct {
		// Naming digests is what lets a per-image button mean one image. An
		// empty list is the whole gap, which is what the bulk button and the
		// snapshot trigger both want.
		ImageDigests []string `json:"imageDigests,omitempty" doc:"Limit the run to these running image digests. Omit to ingest every unknown image the cluster reports."`
	}
}

// IngestUnknownOutput reports what an ingest run did with every unknown image
// it considered.
//
// The skips are broken out by reason rather than summed. A single "skipped"
// number cannot be acted on: adding credentials, enabling a registry and
// fixing a node runtime are different jobs.
type IngestUnknownOutput struct {
	Body struct {
		Considered              int `json:"considered" doc:"Unknown images looked at; the counts below account for all of them"`
		Queued                  int `json:"queued" doc:"Scan jobs enqueued. A multi-arch image expands into one job per platform, so this can exceed the image count."`
		SkippedExisting         int `json:"skippedExisting" doc:"Already has a scan job: scanning, failed, or deleted on purpose. A repeat snapshot lands here."`
		Unauthorized            int `json:"unauthorized" doc:"The host refused the pull, in this run or a recorded earlier one; not retried"`
		EgressDenied            int `json:"egressDenied" doc:"The host is in an address range the egress policy refuses; not retried"`
		SkippedRegistryDisabled int `json:"skippedRegistryDisabled" doc:"The host matches a registry that is switched off"`
		SkippedUnparseableRef   int `json:"skippedUnparseableRef" doc:"The reported reference carries no host to resolve against"`
		Failed                  int `json:"failed" doc:"Submission errored: a manifest that is not there, or a transient registry or queue problem"`
	}
}

// ---------------------------------------------------------------------------
// Agent credentials (ocidex-70eo.5)
// ---------------------------------------------------------------------------

// ClusterCredentialResponse is an agent credential bound to one cluster. Key
// is present only on the response that minted it.
type ClusterCredentialResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix" doc:"First 8 characters of the key"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty" doc:"When the agent last authenticated with it; empty if never"`
	OwnerID    string `json:"ownerId" doc:"User who minted it. The credential narrows with that user's live namespace roles."`
	OwnerName  string `json:"ownerName,omitempty"`
	Key        string `json:"key,omitempty" doc:"The full key, shown once on create or rotate. Store it in the agent's secret."`
	ServerURL  string `json:"serverUrl,omitempty" doc:"The API's configured public URL (API_BASE_URL), for the agent's server.url; absent when not configured. Set only alongside key."`
}

// ConnectClusterInput is the request for POST /api/v1/clusters/connect.
type ConnectClusterInput struct {
	Body struct {
		NamespaceID string `json:"namespaceId" format:"uuid" doc:"Owning namespace UUID"`
		Name        string `json:"name" minLength:"1" maxLength:"100" doc:"Cluster name, unique within the namespace"`
		Description string `json:"description,omitempty" maxLength:"500"`
		AutoIngest  *bool  `json:"autoIngest,omitempty" doc:"Scan running images with no SBOM on each snapshot. Defaults to true."`
	}
}

// ConnectClusterOutput is the response for POST /api/v1/clusters/connect.
type ConnectClusterOutput struct {
	Body struct {
		Cluster    ClusterResponse           `json:"cluster"`
		Credential ClusterCredentialResponse `json:"credential" doc:"The cluster's first agent credential; its key is shown only here"`
	}
}

// ListClusterCredentialsInput is the request for GET /api/v1/clusters/{id}/credentials.
type ListClusterCredentialsInput struct {
	ID string `path:"id" doc:"Cluster UUID" format:"uuid"`
}

// ListClusterCredentialsOutput is the response for GET /api/v1/clusters/{id}/credentials.
type ListClusterCredentialsOutput struct {
	Body struct {
		Data []ClusterCredentialResponse `json:"data"`
	}
}

// CreateClusterCredentialInput is the request for POST /api/v1/clusters/{id}/credentials.
type CreateClusterCredentialInput struct {
	ID   string `path:"id" doc:"Cluster UUID" format:"uuid"`
	Body struct {
		Name string `json:"name,omitempty" maxLength:"100" doc:"Label for the credential; defaults to '<cluster>-agent'"`
	}
}

// ClusterCredentialOutput is the response for creating or rotating a credential.
type ClusterCredentialOutput struct {
	Body ClusterCredentialResponse
}

// ClusterCredentialInput addresses one credential of one cluster.
type ClusterCredentialInput struct {
	ID           string `path:"id" doc:"Cluster UUID" format:"uuid"`
	CredentialID string `path:"credentialId" doc:"Credential UUID" format:"uuid"`
}
