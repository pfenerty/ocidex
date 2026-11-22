package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// remediationPlanFormat is the shape both remediation prompts ask for. It is
// grouped by the action a person takes, not by advisory, because one action
// (a base-image bump, a redeploy) usually clears many advisories at once.
const remediationPlanFormat = `Write the plan grouped by action, most impact first:
1. Redeploy: a newer catalogued version already fixes it; name the version.
2. Rebuild on a current base image: the vulnerable packages come from a base
   image that is not current; name the base and its current version.
3. Package upgrades: name each package, installed -> fixed version (the highest
   fixed version clears every fixable advisory), and the advisories it clears.
   Say whether it is a direct dependency (bump it in the manifest) or
   transitive (bump what pulls it in).
4. No fix available: advisories with no fixed version or marked wont-fix;
   recommend mitigation or a documented risk acceptance, not an upgrade.
5. Unassessed: running images with no SBOM, and stale data, with what closes
   each gap.
Rank inside each group by severity, then by workloads exposed. Cite advisory
ids. Never invent a fixed version a tool did not return.`

// registerPrompts adds the guided workflows. A prompt is a client-side
// shortcut (a slash command in most clients) that hands the model the tool
// sequence and the expected output, so a one-line request produces the same
// thorough plan as a carefully worded one.
func registerPrompts(srv *mcp.Server) {
	srv.AddPrompt(&mcp.Prompt{
		Name:        "remediate_image",
		Title:       "Plan remediation for an image",
		Description: "Build a vulnerability remediation plan for one artifact (usually a container image).",
		Arguments: []*mcp.PromptArgument{
			{Name: "image", Description: "Artifact name, exact or partial, e.g. ghcr.io/acme/api", Required: true},
			{Name: "version", Description: "Version to remediate; defaults to the latest"},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		image := strings.TrimSpace(req.Params.Arguments["image"])
		if image == "" {
			return nil, fmt.Errorf("remediate_image needs an image")
		}
		version := strings.TrimSpace(req.Params.Arguments["version"])
		target := "its latest version"
		if version != "" {
			target = "version " + version
		}
		return userPrompt("Vulnerability remediation plan for "+image, fmt.Sprintf(`Plan vulnerability remediation for %[1]s, %[2]s, using the ocidex tools.

1. Resolve it with ocidex_lookup_artifact. If the name is not exact, use
   ocidex_search_artifacts and pick the match.
2. ocidex_list_artifact_versions: find the target version's sbom_id, and note
   whether a newer version has fewer criticals and highs (then redeploying it
   is the first action).
3. ocidex_sbom_findings with group_by=package on that sbom_id: the vulnerable
   packages, the fixed versions that clear them, and the ones with no fix.
4. ocidex_artifact_lineage: if contains names a base image whose is_current is
   false, check that base with ocidex_list_artifact_versions; packages it
   ships are fixed by rebuilding on its current version.
5. For the worst packages, ocidex_list_sbom_components with name=<package>
   tells direct from transitive, and ocidex_component_versions shows whether
   the fixed version already ships elsewhere.
6. For critical advisories, ocidex_get_vulnerability gives references (the
   upstream patch) and ocidex_vulnerability_workloads shows where it runs.
7. ocidex_data_freshness: say so if matching is behind.

%[3]s`, image, target, remediationPlanFormat)), nil
	})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "remediate_cluster",
		Title:       "Plan remediation for a cluster",
		Description: "Build a vulnerability remediation plan for what a Kubernetes cluster is running right now.",
		Arguments: []*mcp.PromptArgument{
			{Name: "cluster", Description: "Cluster name or id, as listed by ocidex_list_clusters", Required: true},
			{Name: "k8s_namespace", Description: "Limit the plan to one Kubernetes namespace"},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		cluster := strings.TrimSpace(req.Params.Arguments["cluster"])
		if cluster == "" {
			return nil, fmt.Errorf("remediate_cluster needs a cluster")
		}
		scope := ""
		if ns := strings.TrimSpace(req.Params.Arguments["k8s_namespace"]); ns != "" {
			scope = fmt.Sprintf(" Limit the plan to Kubernetes namespace %q: pass k8s_namespace to the inventory tools.", ns)
		}
		return userPrompt("Vulnerability remediation plan for cluster "+cluster, fmt.Sprintf(`Plan vulnerability remediation for cluster %[1]s, using the ocidex tools.%[2]s

1. ocidex_list_clusters: confirm the cluster's health. If it is not healthy,
   the plan describes what ran at last_seen_at; say so up front.
2. ocidex_cluster_vulnerabilities with sort=workloads: the advisories with
   the widest exposure.
3. ocidex_cluster_images: the running images, most vulnerable first. Work
   through them in order; for each, read its version history with
   ocidex_list_artifact_versions (a newer clean version means redeploy), then
   ocidex_sbom_findings group_by=package on its sbom_id, then
   ocidex_artifact_lineage. Many images sharing one stale base image is a
   single rebuild action: group them.
4. ocidex_cluster_workloads: name the Deployments, StatefulSets and DaemonSets
   each action has to roll.
5. ocidex_cluster_coverage_gaps: running images with no SBOM are unassessed
   risk; list them with the registry change that closes each gap.
6. ocidex_data_freshness: say so if matching is behind.

%[3]s`, cluster, scope, remediationPlanFormat)), nil
	})
}

func userPrompt(description, text string) *mcp.GetPromptResult {
	return &mcp.GetPromptResult{
		Description: description,
		Messages:    []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}},
	}
}
