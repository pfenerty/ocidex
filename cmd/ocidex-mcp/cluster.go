package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// resolveCluster turns a cluster name or UUID into a UUID.
//
// The API has no name-keyed cluster resolver, but an agent asked about "the
// homelab cluster" holds a name, so the name is matched against the visible
// list here. Names are unique only within a namespace; when several match, the
// error lists them with their namespaces and ids, the same narrowing contract
// as the ADR-042 lookups.
func resolveCluster(ctx context.Context, api client.Client, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("a cluster name or id is required; call ocidex_list_clusters to see them")
	}
	if uuidPattern.MatchString(ref) {
		return ref, nil
	}
	clusters, err := api.ListClusters(ctx, "")
	if err != nil {
		return "", toolError("listing clusters to resolve "+ref, err)
	}
	var matches []client.ClusterResponse
	for _, c := range clusters {
		if strings.EqualFold(c.Name, ref) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].Id, nil
	case 0:
		return "", fmt.Errorf("no visible cluster is named %q; call ocidex_list_clusters to see the ones this key can read", ref)
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%d clusters are named %q; retry with the id of one:", len(matches), ref)
		for _, c := range matches {
			fmt.Fprintf(&b, "\n- %s (namespace %s)", c.Id, deref(c.NamespaceName))
		}
		return "", fmt.Errorf("%s", b.String())
	}
}

// matchStateHelp explains the four states once; workloads and images share
// them, and an agent misreading "unknown" as "clean" is the mistake that
// matters.
const matchStateHelp = "exact: digest matched an SBOM. index: matched a multi-arch index, platform not pinned. " +
	"unknown: no SBOM ingested for the digest (a coverage gap, not a clean image). " +
	"unresolvable: the agent could not read a digest"

func registerClusterTools(srv *mcp.Server, api client.Client) {
	registerListClusters(srv, api)
	registerClusterVulns(srv, api)
	registerClusterImages(srv, api)
	registerClusterWorkloads(srv, api)
	registerClusterCoverageGaps(srv, api)
	registerVulnerabilityWorkloads(srv, api)
}

type severityCountsOutput struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
}

func toSeverityCounts(v *client.WorkloadVulnCounts) *severityCountsOutput {
	if v == nil {
		return nil
	}
	return &severityCountsOutput{Critical: v.Critical, High: v.High, Medium: v.Medium, Low: v.Low}
}

type coverageOutput struct {
	Total        int64 `json:"total" jsonschema:"Workload-containers reported"`
	Pods         int64 `json:"pods" jsonschema:"Running pods those containers add up to"`
	Matched      int64 `json:"matched" jsonschema:"Matched to an SBOM, exactly or through a multi-arch index"`
	Unknown      int64 `json:"unknown" jsonschema:"Running with no SBOM: their vulnerabilities are not counted anywhere"`
	Unresolvable int64 `json:"unresolvable" jsonschema:"No digest could be read"`
}

func toCoverage(c client.WorkloadCoverageResponse) coverageOutput {
	return coverageOutput{Total: c.Total, Pods: c.Pods, Matched: c.Matched, Unknown: c.Unknown, Unresolvable: c.Unresolvable}
}

type clusterOutput struct {
	ID               string          `json:"id" jsonschema:"UUID of the cluster"`
	Name             string          `json:"name"`
	Namespace        string          `json:"namespace,omitempty" jsonschema:"OCIDex namespace that owns the cluster"`
	Description      string          `json:"description,omitempty"`
	Health           string          `json:"health" jsonschema:"never_reported, healthy, stale, erroring or paused. Anything but healthy means the inventory may be out of date"`
	HealthReason     string          `json:"health_reason,omitempty"`
	LastSeenAt       string          `json:"last_seen_at,omitempty" jsonschema:"When the agent last pushed an inventory"`
	RunningCriticals int64           `json:"running_criticals" jsonschema:"Distinct critical vulnerabilities in matched running images"`
	Coverage         *coverageOutput `json:"coverage,omitempty"`
}

type listClustersInput struct{}

type listClustersOutput struct {
	Clusters []clusterOutput `json:"clusters" jsonschema:"Clusters this key can see"`
}

func registerListClusters(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_list_clusters",
		Description: "List the Kubernetes clusters reporting their running workloads to OCIDex, with health, " +
			"running critical count and SBOM coverage. This is the entry point for any question about what " +
			"is actually deployed. Check health before trusting a cluster's answers: a stale cluster " +
			"describes what ran when it last reported.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listClustersInput) (*mcp.CallToolResult, listClustersOutput, error) {
		clusters, err := api.ListClusters(ctx, "")
		if err != nil {
			return nil, listClustersOutput{}, toolError("listing clusters", err)
		}
		out := listClustersOutput{Clusters: make([]clusterOutput, 0, len(clusters))}
		for _, c := range clusters {
			row := clusterOutput{
				ID:           c.Id,
				Name:         c.Name,
				Namespace:    deref(c.NamespaceName),
				Description:  deref(c.Description),
				Health:       string(c.Health.State),
				HealthReason: deref(c.Health.Reason),
				LastSeenAt:   deref(c.LastSeenAt),
			}
			if c.Summary != nil {
				row.RunningCriticals = c.Summary.RunningCriticals
				cov := toCoverage(c.Summary.Coverage)
				row.Coverage = &cov
			}
			out.Clusters = append(out.Clusters, row)
		}
		return nil, out, nil
	})
}

type clusterVulnsInput struct {
	Cluster  string `json:"cluster" jsonschema:"Cluster name or UUID, as returned by ocidex_list_clusters"`
	Severity string `json:"severity,omitempty" jsonschema:"Only this severity: critical, high, medium, low or unknown (any case)"`
	Sort     string `json:"sort,omitempty" jsonschema:"worst (default): severity then CVSS. workloads: most running workloads exposed first, the blast-radius order"`
	Limit    int32  `json:"limit,omitempty" jsonschema:"Maximum advisories to return; defaults to 50"`
	Offset   int32  `json:"offset,omitempty" jsonschema:"Advisories to skip, for paging"`
}

type runningVulnOutput struct {
	ID            string  `json:"id" jsonschema:"Canonical advisory id; pass it to ocidex_vulnerability_workloads to see which workloads run it"`
	Severity      string  `json:"severity,omitempty"`
	CvssScore     float64 `json:"cvss_score,omitempty"`
	Summary       string  `json:"summary,omitempty"`
	WorkloadCount int64   `json:"workload_count" jsonschema:"Distinct running workloads in this cluster carrying it"`
}

type clusterVulnsOutput struct {
	ClusterID       string              `json:"cluster_id"`
	Vulnerabilities []runningVulnOutput `json:"vulnerabilities"`
	Total           int64               `json:"total"`
	Limit           int32               `json:"limit"`
	Offset          int32               `json:"offset"`
	NextOffset      int32               `json:"next_offset,omitempty" jsonschema:"Pass as offset to get the next page; absent on the last page"`
	Coverage        coverageOutput      `json:"coverage" jsonschema:"How much of the cluster these counts cover; unknown workloads carry vulnerabilities that are not listed"`
}

func registerClusterVulns(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_cluster_vulnerabilities",
		Description: "List the vulnerabilities in images a cluster is running right now, each with the number of " +
			"workloads exposed. This is the first call for cluster remediation. Sort by workloads to find " +
			"the fix with the widest effect. Then use ocidex_cluster_images to map advisories to the images " +
			"(and their sbom_ids) that carry them. Read coverage: images with no SBOM are not counted.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterVulnsInput) (*mcp.CallToolResult, clusterVulnsOutput, error) {
		id, err := resolveCluster(ctx, api, in.Cluster)
		if err != nil {
			return nil, clusterVulnsOutput{}, err
		}
		sev, err := severityParam[client.ListClusterVulnsParamsSeverity](in.Severity)
		if err != nil {
			return nil, clusterVulnsOutput{}, err
		}
		params := client.ListClusterVulnsParams{
			Severity: sev,
			Limit:    optionalInt32(int(pageLimit(in.Limit, defaultSearchLimit))),
			Offset:   optionalInt32(int(in.Offset)),
		}
		switch in.Sort {
		case "", "worst":
		case "workloads":
			s, d := client.ListClusterVulnsParamsSort("workloadCount"), client.ListClusterVulnsParamsDir(sortDescending)
			params.Sort, params.Dir = &s, &d
		default:
			return nil, clusterVulnsOutput{}, fmt.Errorf("sort %q is not worst or workloads", in.Sort)
		}
		res, err := api.ListClusterVulns(ctx, id, params)
		if err != nil {
			return nil, clusterVulnsOutput{}, toolError("listing vulnerabilities for cluster "+in.Cluster, err)
		}
		out := clusterVulnsOutput{
			ClusterID:       id,
			Vulnerabilities: make([]runningVulnOutput, 0, len(derefSlice(res.Data))),
			Total:           res.Pagination.Total,
			Limit:           res.Pagination.Limit,
			Offset:          res.Pagination.Offset,
			Coverage:        toCoverage(res.Coverage),
		}
		for _, v := range derefSlice(res.Data) {
			out.Vulnerabilities = append(out.Vulnerabilities, runningVulnOutput{
				ID:            v.CanonicalId,
				Severity:      deref(v.Severity),
				CvssScore:     float32Value(v.CvssScore),
				Summary:       deref(v.Summary),
				WorkloadCount: v.WorkloadCount,
			})
		}
		return nil, out, nil
	})
}

type clusterInventoryInput struct {
	Cluster      string `json:"cluster" jsonschema:"Cluster name or UUID, as returned by ocidex_list_clusters"`
	K8sNamespace string `json:"k8s_namespace,omitempty" jsonschema:"Only this Kubernetes namespace"`
	MatchState   string `json:"match_state,omitempty" jsonschema:"Only this match state: exact, index, unknown or unresolvable"`
	Query        string `json:"query,omitempty" jsonschema:"Substring over workload name, container name and image reference"`
	Limit        int32  `json:"limit,omitempty" jsonschema:"Maximum rows to return; defaults to 50"`
	Offset       int32  `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

// validMatchState checks a match-state filter before it reaches the API.
func validMatchState(s string) error {
	switch s {
	case "", "exact", "index", "unknown", "unresolvable":
		return nil
	}
	return fmt.Errorf("match_state %q is not exact, index, unknown or unresolvable", s)
}

type clusterImageOutput struct {
	ImageRef        string                `json:"image_ref"`
	ImageDigest     string                `json:"image_digest,omitempty"`
	MatchState      string                `json:"match_state" jsonschema:"exact, index, unknown or unresolvable"`
	ArtifactID      string                `json:"artifact_id,omitempty" jsonschema:"Matched artifact; pass to ocidex_artifact_lineage or ocidex_list_artifact_versions"`
	ArtifactName    string                `json:"artifact_name,omitempty"`
	ArtifactVersion string                `json:"artifact_version,omitempty" jsonschema:"Version that is running"`
	SBOMID          string                `json:"sbom_id,omitempty" jsonschema:"SBOM of the running image; pass to ocidex_sbom_findings with group_by package for its fix list"`
	Vulns           *severityCountsOutput `json:"vulns,omitempty" jsonschema:"Severity counts of the running image; absent when unmatched"`
	WorkloadCount   int64                 `json:"workload_count"`
	PodCount        int64                 `json:"pod_count"`
	NamespaceCount  int64                 `json:"namespace_count"`
	SampleWorkload  string                `json:"sample_workload,omitempty" jsonschema:"One workload running it, as namespace/name"`
	LastSeenAt      string                `json:"last_seen_at"`
}

type clusterImagesOutput struct {
	ClusterID  string               `json:"cluster_id"`
	Images     []clusterImageOutput `json:"images" jsonschema:"Running images, most vulnerable first"`
	Total      int64                `json:"total"`
	Limit      int32                `json:"limit"`
	Offset     int32                `json:"offset"`
	NextOffset int32                `json:"next_offset,omitempty" jsonschema:"Pass as offset to get the next page; absent on the last page"`
	Coverage   coverageOutput       `json:"coverage"`
}

func registerClusterImages(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_cluster_images",
		Description: "List the distinct images a cluster is running, most vulnerable first, each with its matched " +
			"artifact, running version, sbom_id, severity counts and how many workloads run it. This is how " +
			"cluster remediation becomes per-image work: take each image's sbom_id to ocidex_sbom_findings, " +
			"and its artifact_id to ocidex_list_artifact_versions to see whether a newer release already " +
			"fixes it (then the fix is a redeploy, not a rebuild). " + matchStateHelp + ".",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterInventoryInput) (*mcp.CallToolResult, clusterImagesOutput, error) {
		id, err := resolveCluster(ctx, api, in.Cluster)
		if err != nil {
			return nil, clusterImagesOutput{}, err
		}
		if err := validMatchState(in.MatchState); err != nil {
			return nil, clusterImagesOutput{}, err
		}
		s, d := client.ListClusterImagesParamsSort("vulnCount"), client.ListClusterImagesParamsDir(sortDescending)
		params := client.ListClusterImagesParams{
			K8sNamespace: optional(in.K8sNamespace),
			Q:            optional(in.Query),
			Sort:         &s,
			Dir:          &d,
			Limit:        optionalInt32(int(pageLimit(in.Limit, defaultSearchLimit))),
			Offset:       optionalInt32(int(in.Offset)),
		}
		if in.MatchState != "" {
			m := client.ListClusterImagesParamsMatchState(in.MatchState)
			params.MatchState = &m
		}
		res, err := api.ListClusterImages(ctx, id, params)
		if err != nil {
			return nil, clusterImagesOutput{}, toolError("listing images for cluster "+in.Cluster, err)
		}
		out := clusterImagesOutput{
			ClusterID: id,
			Images:    make([]clusterImageOutput, 0, len(derefSlice(res.Data))),
			Total:     res.Pagination.Total,
			Limit:     res.Pagination.Limit,
			Offset:    res.Pagination.Offset,
			Coverage:  toCoverage(res.Coverage),
		}
		for _, img := range derefSlice(res.Data) {
			row := clusterImageOutput{
				ImageRef:        img.ImageRef,
				ImageDigest:     deref(img.ImageDigest),
				MatchState:      string(img.MatchState),
				ArtifactID:      deref(img.ArtifactId),
				ArtifactName:    deref(img.ArtifactName),
				ArtifactVersion: deref(img.SubjectVersion),
				SBOMID:          deref(img.SbomId),
				Vulns:           toSeverityCounts(img.Vulns),
				WorkloadCount:   img.WorkloadCount,
				PodCount:        img.PodCount,
				NamespaceCount:  img.NamespaceCount,
				LastSeenAt:      img.LastSeenAt,
			}
			if img.SampleWorkload != nil {
				row.SampleWorkload = deref(img.SampleNamespace) + "/" + *img.SampleWorkload
			}
			out.Images = append(out.Images, row)
		}
		return nil, out, nil
	})
}

type workloadOutput struct {
	ClusterID       string                `json:"cluster_id,omitempty"`
	ClusterName     string                `json:"cluster_name,omitempty"`
	K8sNamespace    string                `json:"k8s_namespace"`
	WorkloadKind    string                `json:"workload_kind" jsonschema:"Deployment, StatefulSet, DaemonSet, Job, ..."`
	WorkloadName    string                `json:"workload_name"`
	ContainerName   string                `json:"container_name"`
	ImageRef        string                `json:"image_ref"`
	MatchState      string                `json:"match_state"`
	ArtifactID      string                `json:"artifact_id,omitempty"`
	ArtifactName    string                `json:"artifact_name,omitempty"`
	ArtifactVersion string                `json:"artifact_version,omitempty"`
	SBOMID          string                `json:"sbom_id,omitempty"`
	Vulns           *severityCountsOutput `json:"vulns,omitempty"`
	PodCount        int32                 `json:"pod_count"`
	LastSeenAt      string                `json:"last_seen_at"`
}

type clusterWorkloadsOutput struct {
	ClusterID  string           `json:"cluster_id"`
	Workloads  []workloadOutput `json:"workloads" jsonschema:"Workload-containers, most vulnerable first"`
	Total      int64            `json:"total"`
	Limit      int32            `json:"limit"`
	Offset     int32            `json:"offset"`
	NextOffset int32            `json:"next_offset,omitempty" jsonschema:"Pass as offset to get the next page; absent on the last page"`
	Coverage   coverageOutput   `json:"coverage"`
}

func registerClusterWorkloads(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_cluster_workloads",
		Description: "List a cluster's workloads (one row per workload container), most vulnerable first, with the " +
			"image, matched artifact and severity counts of each. Use it when the plan has to name the " +
			"Deployments or StatefulSets to roll, or to scope remediation to one Kubernetes namespace. " +
			matchStateHelp + ".",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clusterInventoryInput) (*mcp.CallToolResult, clusterWorkloadsOutput, error) {
		id, err := resolveCluster(ctx, api, in.Cluster)
		if err != nil {
			return nil, clusterWorkloadsOutput{}, err
		}
		if err := validMatchState(in.MatchState); err != nil {
			return nil, clusterWorkloadsOutput{}, err
		}
		s, d := client.ListClusterWorkloadsParamsSort("vulnCount"), client.ListClusterWorkloadsParamsDir(sortDescending)
		params := client.ListClusterWorkloadsParams{
			K8sNamespace: optional(in.K8sNamespace),
			Q:            optional(in.Query),
			Sort:         &s,
			Dir:          &d,
			Limit:        optionalInt32(int(pageLimit(in.Limit, defaultSearchLimit))),
			Offset:       optionalInt32(int(in.Offset)),
		}
		if in.MatchState != "" {
			m := client.ListClusterWorkloadsParamsMatchState(in.MatchState)
			params.MatchState = &m
		}
		res, err := api.ListClusterWorkloadsPage(ctx, id, params)
		if err != nil {
			return nil, clusterWorkloadsOutput{}, toolError("listing workloads for cluster "+in.Cluster, err)
		}
		out := clusterWorkloadsOutput{
			ClusterID: id,
			Workloads: make([]workloadOutput, 0, len(derefSlice(res.Data))),
			Total:     res.Pagination.Total,
			Limit:     res.Pagination.Limit,
			Offset:    res.Pagination.Offset,
			Coverage:  toCoverage(res.Coverage),
		}
		for _, w := range derefSlice(res.Data) {
			out.Workloads = append(out.Workloads, workloadOutput{
				ClusterID:       w.ClusterId,
				K8sNamespace:    w.K8sNamespace,
				WorkloadKind:    w.WorkloadKind,
				WorkloadName:    w.WorkloadName,
				ContainerName:   w.ContainerName,
				ImageRef:        w.ImageRef,
				MatchState:      string(w.MatchState),
				ArtifactID:      deref(w.ArtifactId),
				ArtifactName:    deref(w.ArtifactName),
				ArtifactVersion: deref(w.SubjectVersion),
				SBOMID:          deref(w.SbomId),
				Vulns:           toSeverityCounts(w.Vulns),
				PodCount:        w.PodCount,
				LastSeenAt:      w.LastSeenAt,
			})
		}
		return nil, out, nil
	})
}

type coverageGapsInput struct {
	Cluster string `json:"cluster" jsonschema:"Cluster name or UUID, as returned by ocidex_list_clusters"`
	Limit   int32  `json:"limit,omitempty" jsonschema:"Maximum images to return; defaults to 50"`
	Offset  int32  `json:"offset,omitempty" jsonschema:"Images to skip, for paging"`
}

type unknownImageOutput struct {
	ImageRef       string `json:"image_ref"`
	ImageDigest    string `json:"image_digest"`
	Reason         string `json:"reason" jsonschema:"Why it has no SBOM, and so what fixes the gap: ready (queued for the next scan), scanning, failed (manifest missing or retries used up), unauthorized (add registry credentials), registry_disabled (switch the registry on), egress_denied (host is in a range egress policy refuses), unparseable_ref (reference names no host), deleted"`
	RegistryName   string `json:"registry_name,omitempty" jsonschema:"Configured registry that serves it, if any"`
	RegistryHost   string `json:"registry_host,omitempty"`
	WorkloadCount  int64  `json:"workload_count"`
	PodCount       int64  `json:"pod_count"`
	SampleWorkload string `json:"sample_workload,omitempty" jsonschema:"One workload running it, as namespace/name"`
}

type gapHostOutput struct {
	Scope           string   `json:"scope" jsonschema:"Registry scope to configure, e.g. ghcr.io/acme"`
	Reason          string   `json:"reason" jsonschema:"The remedy: unauthorized means fix or add credentials for this scope, registry_disabled means switch its registry on"`
	RegistryName    string   `json:"registry_name,omitempty"`
	ImageCount      int64    `json:"image_count"`
	WorkloadCount   int64    `json:"workload_count"`
	Repositories    []string `json:"repositories,omitempty" jsonschema:"Sample of repositories behind the gap; capped, compare repository_count"`
	RepositoryCount int64    `json:"repository_count"`
}

type coverageGapsOutput struct {
	ClusterID       string               `json:"cluster_id"`
	Images          []unknownImageOutput `json:"images" jsonschema:"Running images with no SBOM"`
	Hosts           []gapHostOutput      `json:"by_registry" jsonschema:"The same gap grouped by the registry change that would close it"`
	Reasons         map[string]int64     `json:"reasons" jsonschema:"Image counts per reason"`
	ScanningEnabled bool                 `json:"scanning_enabled" jsonschema:"Whether OCIDex will scan these images itself once a registry can serve them"`
	Total           int64                `json:"total"`
	Limit           int32                `json:"limit"`
	Offset          int32                `json:"offset"`
	NextOffset      int32                `json:"next_offset,omitempty" jsonschema:"Pass as offset to get the next page; absent on the last page"`
}

func registerClusterCoverageGaps(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_cluster_coverage_gaps",
		Description: "List the images a cluster runs that have no SBOM, so OCIDex cannot see their " +
			"vulnerabilities, each with the reason and the registry change that would close the gap. " +
			"A remediation plan for a cluster is incomplete without this: list these images as unassessed " +
			"risk rather than treating them as clean.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in coverageGapsInput) (*mcp.CallToolResult, coverageGapsOutput, error) {
		id, err := resolveCluster(ctx, api, in.Cluster)
		if err != nil {
			return nil, coverageGapsOutput{}, err
		}
		res, err := api.ListClusterUnknownImages(ctx, id, client.ListClusterUnknownImagesParams{
			Limit:  optionalInt32(int(pageLimit(in.Limit, defaultSearchLimit))),
			Offset: optionalInt32(int(in.Offset)),
		})
		if err != nil {
			return nil, coverageGapsOutput{}, toolError("listing coverage gaps for cluster "+in.Cluster, err)
		}
		r := res.Reasons
		out := coverageGapsOutput{
			ClusterID: id,
			Images:    make([]unknownImageOutput, 0, len(derefSlice(res.Data))),
			Hosts:     make([]gapHostOutput, 0, len(derefSlice(res.Hosts))),
			Reasons: map[string]int64{
				"ready": r.Ready, "scanning": r.Scanning, "failed": r.Failed, "unauthorized": r.Unauthorized,
				"registry_disabled": r.RegistryDisabled, "egress_denied": r.EgressDenied,
				"unparseable_ref": r.UnparseableRef, "deleted": r.Deleted,
			},
			ScanningEnabled: res.ScanningEnabled,
			Total:           res.Pagination.Total,
			Limit:           res.Pagination.Limit,
			Offset:          res.Pagination.Offset,
		}
		for _, img := range derefSlice(res.Data) {
			row := unknownImageOutput{
				ImageRef:      img.ImageRef,
				ImageDigest:   img.ImageDigest,
				Reason:        string(img.Reason),
				RegistryName:  deref(img.RegistryName),
				RegistryHost:  deref(img.RegistryHost),
				WorkloadCount: img.WorkloadCount,
				PodCount:      img.PodCount,
			}
			if img.SampleWorkloadName != nil {
				row.SampleWorkload = deref(img.SampleK8sNamespace) + "/" + *img.SampleWorkloadName
			}
			out.Images = append(out.Images, row)
		}
		for _, h := range derefSlice(res.Hosts) {
			out.Hosts = append(out.Hosts, gapHostOutput{
				Scope:           h.Scope,
				Reason:          string(h.Reason),
				RegistryName:    deref(h.RegistryName),
				ImageCount:      h.ImageCount,
				WorkloadCount:   h.WorkloadCount,
				Repositories:    derefSlice(h.Repositories),
				RepositoryCount: h.RepositoryCount,
			})
		}
		return nil, out, nil
	})
}

type vulnWorkloadsInput struct {
	VulnID  string `json:"vuln_id" jsonschema:"CVE or GHSA identifier"`
	Cluster string `json:"cluster,omitempty" jsonschema:"Only this cluster, by name or UUID; omit for every visible cluster"`
	Limit   int32  `json:"limit,omitempty" jsonschema:"Maximum workloads to return; defaults to 50"`
}

type vulnWorkloadsOutput struct {
	VulnID    string           `json:"vuln_id"`
	Workloads []workloadOutput `json:"workloads" jsonschema:"Running workloads whose image carries the advisory"`
}

func registerVulnerabilityWorkloads(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_vulnerability_workloads",
		Description: "List the Kubernetes workloads currently running an image that carries one advisory, across " +
			"every visible cluster or one. Use it to answer \"are we exposed to CVE-X in production, and " +
			"where\", and to name the exact workloads a fix must roll out to.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in vulnWorkloadsInput) (*mcp.CallToolResult, vulnWorkloadsOutput, error) {
		params := client.ListVulnerabilityWorkloadsParams{
			Limit: optionalInt32(int(pageLimit(in.Limit, defaultSearchLimit))),
		}
		if in.Cluster != "" {
			id, err := resolveCluster(ctx, api, in.Cluster)
			if err != nil {
				return nil, vulnWorkloadsOutput{}, err
			}
			params.ClusterId = &id
		}
		rows, err := api.ListVulnerabilityWorkloads(ctx, in.VulnID, params)
		if err != nil {
			return nil, vulnWorkloadsOutput{}, toolError("listing workloads running "+in.VulnID, err)
		}
		out := vulnWorkloadsOutput{VulnID: in.VulnID, Workloads: make([]workloadOutput, 0, len(rows))}
		for _, w := range rows {
			out.Workloads = append(out.Workloads, workloadOutput{
				ClusterID:       w.ClusterId,
				ClusterName:     w.ClusterName,
				K8sNamespace:    w.K8sNamespace,
				WorkloadKind:    w.WorkloadKind,
				WorkloadName:    w.WorkloadName,
				ContainerName:   w.ContainerName,
				ImageRef:        w.ImageRef,
				MatchState:      string(w.MatchState),
				ArtifactID:      deref(w.ArtifactId),
				ArtifactName:    deref(w.ArtifactName),
				ArtifactVersion: deref(w.SubjectVersion),
				SBOMID:          deref(w.SbomId),
				Vulns:           toSeverityCounts(w.Vulns),
				PodCount:        w.PodCount,
				LastSeenAt:      w.LastSeenAt,
			})
		}
		return nil, out, nil
	})
}
