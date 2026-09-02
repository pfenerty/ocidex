package main

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// defaultChangeLimit bounds a diff answer. A release that rebases its base
// image changes hundreds of packages, and the first page plus an accurate total
// tells a model more than a truncated dump of all of them would.
const defaultChangeLimit = 50

// defaultRootLimit bounds the dependency-tree summary. Roots are direct
// dependencies, so there are far fewer of them than components, but a large
// application still has more than a model needs to see at once.
const defaultRootLimit = 20

// registerAnalysisTools adds the tools that answer questions about change and
// risk, plus the one write tool.
func registerAnalysisTools(srv *mcp.Server, api client.Client) {
	registerDiffTools(srv, api)
	registerChangelogTool(srv, api)
	registerVulnTools(srv, api)
	registerIngestTool(srv, api)
}

// changeOutput is one component-level change. It carries both versions because
// "upgraded" without the pair of versions is not an answer a model can report.
type changeOutput struct {
	Direction       string `json:"direction" jsonschema:"One of added, removed, upgraded, downgraded, modified"`
	Name            string `json:"name" jsonschema:"Component name"`
	Group           string `json:"group,omitempty" jsonschema:"Component group, where the ecosystem has one"`
	Purl            string `json:"purl,omitempty" jsonschema:"Package URL of the component"`
	Type            string `json:"type" jsonschema:"CycloneDX component type, e.g. library"`
	PreviousVersion string `json:"previous_version,omitempty" jsonschema:"Version in the from-SBOM; absent for an addition"`
	Version         string `json:"version,omitempty" jsonschema:"Version in the to-SBOM; absent for a removal"`
	NodeRef         string `json:"node_ref,omitempty" jsonschema:"Component id of this change in the dependency tree; pass as node to ocidex_diff_tree to see what depends on it"`
}

// changeSummaryOutput is the histogram every diff answer leads with, so a model
// can decide whether to page through the changes at all.
type changeSummaryOutput struct {
	Added      int64 `json:"added"`
	Removed    int64 `json:"removed"`
	Upgraded   int64 `json:"upgraded"`
	Downgraded int64 `json:"downgraded"`
	Modified   int64 `json:"modified"`
}

type sbomRefOutput struct {
	ID           string `json:"id" jsonschema:"UUID of the SBOM"`
	Version      string `json:"version,omitempty" jsonschema:"Artifact version this SBOM describes"`
	Architecture string `json:"architecture,omitempty" jsonschema:"Architecture qualifier"`
	Flavor       string `json:"flavor,omitempty" jsonschema:"Image flavor qualifier (ADR-020)"`
}

type diffOutput struct {
	From      sbomRefOutput       `json:"from" jsonschema:"The SBOM diffed from"`
	To        sbomRefOutput       `json:"to" jsonschema:"The SBOM diffed to"`
	Summary   changeSummaryOutput `json:"summary" jsonschema:"Counts by direction across the whole diff, not just the returned page"`
	Changes   []changeOutput      `json:"changes" jsonschema:"The requested page of changes"`
	Total     int64               `json:"total" jsonschema:"Changes matching the direction filter, across all pages"`
	Truncated bool                `json:"truncated" jsonschema:"Whether more changes matched than were returned"`
}

type diffSBOMsInput struct {
	FromSBOMID string `json:"from_sbom_id" jsonschema:"UUID of the older SBOM"`
	ToSBOMID   string `json:"to_sbom_id" jsonschema:"UUID of the newer SBOM"`
	Direction  string `json:"direction,omitempty" jsonschema:"Return only changes of one kind: added, removed, upgraded, downgraded or modified"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum changes to return; defaults to 50"`
	Offset     int    `json:"offset,omitempty" jsonschema:"Changes to skip, for paging through a large diff"`
}

func toSBOMRefOutput(r client.SBOMRef) sbomRefOutput {
	return sbomRefOutput{
		ID:           r.Id,
		Version:      deref(r.SubjectVersion),
		Architecture: deref(r.Architecture),
		Flavor:       deref(r.Flavor),
	}
}

func toChangeSummaryOutput(s client.ChangeSummary) changeSummaryOutput {
	return changeSummaryOutput{
		Added:      s.Added,
		Removed:    s.Removed,
		Upgraded:   s.Upgraded,
		Downgraded: s.Downgraded,
		Modified:   s.Modified,
	}
}

func toChangeOutput(c client.ComponentDiff) changeOutput {
	return changeOutput{
		Direction:       c.Direction,
		Name:            c.Name,
		Group:           deref(c.Group),
		Purl:            deref(c.Purl),
		Type:            c.Type,
		PreviousVersion: deref(c.PreviousVersion),
		Version:         deref(c.Version),
		NodeRef:         deref(c.NodeRef),
	}
}

// selectChanges applies the direction filter and the page window. Filtering
// happens here rather than in the API because the diff endpoint returns the
// whole comparison in one response; the point of the window is what reaches the
// model, not what crosses the network.
func selectChanges(all []client.ComponentDiff, direction string, limit, offset int) (page []changeOutput, total int64) {
	matched := make([]client.ComponentDiff, 0, len(all))
	for _, c := range all {
		if direction == "" || c.Direction == direction {
			matched = append(matched, c)
		}
	}
	total = int64(len(matched))

	if offset > len(matched) {
		offset = len(matched)
	}
	matched = matched[offset:]
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}

	page = make([]changeOutput, 0, len(matched))
	for _, c := range matched {
		page = append(page, toChangeOutput(c))
	}
	return page, total
}

func registerDiffTools(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_diff_sboms",
		Description: "Compare two SBOMs and report what changed between them, as counts by direction " +
			"plus a page of individual component changes. Get the two ids from ocidex_lookup_sbom. " +
			"Filter with direction and page with limit and offset when the summary shows more changes " +
			"than you need to read; the summary counts always describe the whole diff. To find out " +
			"what pulled a changed component in, pass its node_ref to ocidex_diff_tree.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in diffSBOMsInput) (*mcp.CallToolResult, diffOutput, error) {
		entry, err := api.DiffSBOMs(ctx, in.FromSBOMID, in.ToSBOMID)
		if err != nil {
			return nil, diffOutput{}, toolError(fmt.Sprintf("diffing SBOM %s against %s", in.FromSBOMID, in.ToSBOMID), err)
		}

		limit := in.Limit
		if limit <= 0 {
			limit = defaultChangeLimit
		}
		changes, total := selectChanges(derefSlice(entry.Changes), in.Direction, limit, in.Offset)
		return nil, diffOutput{
			From:      toSBOMRefOutput(entry.From),
			To:        toSBOMRefOutput(entry.To),
			Summary:   toChangeSummaryOutput(entry.Summary),
			Changes:   changes,
			Total:     total,
			Truncated: int64(in.Offset+len(changes)) < total,
		}, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_diff_tree",
		Description: "Explain where the changes between two SBOMs come from, by walking the dependency " +
			"tree instead of listing components flat. Called without node it returns the direct " +
			"dependencies, ordered by how many changes sit beneath each one, which is how to find the " +
			"one upgrade that dragged in fifty transitive changes. Called with a node — a component id " +
			"from this tool or a node_ref from ocidex_diff_sboms — it returns that component's own " +
			"change and its direct children, so you can descend one level at a time.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in diffTreeInput) (*mcp.CallToolResult, diffTreeOutput, error) {
		tree, err := api.GetDiffTree(ctx, in.FromSBOMID, in.ToSBOMID)
		if err != nil {
			return nil, diffTreeOutput{}, toolError(
				fmt.Sprintf("building the diff tree for %s against %s", in.FromSBOMID, in.ToSBOMID), err)
		}
		limit := in.Limit
		if limit <= 0 {
			limit = defaultRootLimit
		}
		return nil, summariseTree(tree, in.Node, limit), nil
	})
}

type diffTreeInput struct {
	FromSBOMID string `json:"from_sbom_id" jsonschema:"UUID of the older SBOM"`
	ToSBOMID   string `json:"to_sbom_id" jsonschema:"UUID of the newer SBOM"`
	Node       string `json:"node,omitempty" jsonschema:"Component id to descend into; omit to start at the direct dependencies"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum entries to return; defaults to 20"`
}

// treeNodeOutput is one rung of the walk: what the component is, whether it
// changed itself, and how much changed underneath it. DescendantChanges is what
// makes the walk worth doing — it is the signal for which branch to descend.
type treeNodeOutput struct {
	ID                string              `json:"id" jsonschema:"Component id; pass as node to descend into this subtree"`
	Name              string              `json:"name" jsonschema:"Component name"`
	Version           string              `json:"version,omitempty" jsonschema:"Component version in the newer SBOM"`
	Purl              string              `json:"purl,omitempty" jsonschema:"Package URL of the component"`
	IsDirect          bool                `json:"is_direct" jsonschema:"Whether this is a direct dependency of the artifact"`
	DescendantChanges changeSummaryOutput `json:"descendant_changes" jsonschema:"Changes below this component in the tree"`
	TotalDescendant   int64               `json:"total_descendant_changes" jsonschema:"Sum of descendant_changes; the ordering key"`
}

type diffTreeOutput struct {
	From       sbomRefOutput       `json:"from" jsonschema:"The SBOM diffed from"`
	To         sbomRefOutput       `json:"to" jsonschema:"The SBOM diffed to"`
	Summary    changeSummaryOutput `json:"summary" jsonschema:"Counts by direction across the whole diff"`
	Node       *treeNodeOutput     `json:"node,omitempty" jsonschema:"The component that was descended into, when node was given"`
	NodeChange *changeOutput       `json:"node_change,omitempty" jsonschema:"The change to that component itself, if it changed"`
	Children   []treeNodeOutput    `json:"children" jsonschema:"Direct dependencies, or the children of node, ordered by total_descendant_changes"`
	Total      int64               `json:"total_children" jsonschema:"Children before the limit was applied"`
}

// summariseTree turns ADR-021's render-oriented DiffTree — nodes, bom-ref
// edges, roots and per-change node refs, all meant for a frontend that draws
// the whole graph — into one level of a walk.
//
// The reduction is the point of the tool: the raw response is large and
// answers "how do I draw this", whereas a model needs "which branch should I
// look at next", which is the descendant-change count and nothing else.
func summariseTree(tree client.DiffTree, node string, limit int) diffTreeOutput {
	nodes := derefSlice(tree.Nodes)
	edges := derefSlice(tree.Edges)
	changes := derefSlice(tree.Changes)

	byID := make(map[string]client.ComponentSummary, len(nodes))
	byBomRef := make(map[string]client.ComponentSummary, len(nodes))
	for _, n := range nodes {
		byID[n.Id] = n
		if n.BomRef != nil {
			byBomRef[*n.BomRef] = n
		}
	}

	out := diffTreeOutput{
		From:    toSBOMRefOutput(tree.From),
		To:      toSBOMRefOutput(tree.To),
		Summary: toChangeSummaryOutput(tree.Summary),
	}

	var refs []string
	if node == "" {
		refs = derefSlice(tree.Roots)
	} else {
		refs = childRefs(byID[node], edges)
		if summary, ok := byID[node]; ok {
			n := toTreeNodeOutput(summary)
			out.Node = &n
		}
		for _, c := range changes {
			if c.NodeRef != nil && *c.NodeRef == node {
				change := toChangeOutput(c)
				out.NodeChange = &change
				break
			}
		}
	}

	children := make([]treeNodeOutput, 0, len(refs))
	for _, ref := range refs {
		// Roots and edges are keyed by bom-ref, while a node passed back in is a
		// component id; accept either so the caller never has to know which
		// identifier a given field carried.
		summary, ok := byBomRef[ref]
		if !ok {
			if summary, ok = byID[ref]; !ok {
				continue
			}
		}
		children = append(children, toTreeNodeOutput(summary))
	}

	// Descending order by blast radius, with the name as the tiebreak so the
	// same tree reads identically twice.
	sort.SliceStable(children, func(i, j int) bool {
		if children[i].TotalDescendant != children[j].TotalDescendant {
			return children[i].TotalDescendant > children[j].TotalDescendant
		}
		return children[i].Name < children[j].Name
	})

	out.Total = int64(len(children))
	if limit > 0 && len(children) > limit {
		children = children[:limit]
	}
	out.Children = children
	return out
}

// childRefs finds the bom-refs a node depends on. Edges are keyed by bom-ref,
// so a node without one has no discoverable children.
func childRefs(node client.ComponentSummary, edges []client.DependencyEdge) []string {
	if node.BomRef == nil {
		return nil
	}
	var refs []string
	for _, e := range edges {
		if e.From == *node.BomRef {
			refs = append(refs, e.To)
		}
	}
	return refs
}

func toTreeNodeOutput(n client.ComponentSummary) treeNodeOutput {
	out := treeNodeOutput{
		ID:       n.Id,
		Name:     n.Name,
		Version:  deref(n.Version),
		Purl:     deref(n.Purl),
		IsDirect: n.IsDirect,
	}
	if n.DescendantChanges != nil {
		d := *n.DescendantChanges
		out.DescendantChanges = changeSummaryOutput{
			Added:      d.Added,
			Removed:    d.Removed,
			Upgraded:   d.Upgraded,
			Downgraded: d.Downgraded,
			Modified:   d.Modified,
		}
		out.TotalDescendant = d.Added + d.Removed + d.Upgraded + d.Downgraded + d.Modified
	}
	return out
}

type artifactVulnsInput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the artifact, as returned by ocidex_lookup_artifact"`
}

type artifactVulnsOutput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the artifact this summary covers"`
	Critical   int64  `json:"critical"`
	High       int64  `json:"high"`
	Medium     int64  `json:"medium"`
	Low        int64  `json:"low"`
	Unknown    int64  `json:"unknown"`
	Total      int64  `json:"total" jsonschema:"Total vulnerabilities across the artifact's SBOMs"`
}

type componentVulnsInput struct {
	ComponentID string `json:"component_id" jsonschema:"Component id, as returned by ocidex_search_components"`
}

type vulnEntryOutput struct {
	ID           string  `json:"id" jsonschema:"Advisory id to pass to ocidex_get_vulnerability"`
	Severity     string  `json:"severity" jsonschema:"critical, high, medium, low or unknown"`
	CvssScore    float64 `json:"cvss_score,omitempty" jsonschema:"CVSS base score, where the advisory has one"`
	FixedVersion string  `json:"fixed_version,omitempty" jsonschema:"Version that fixes it; absent means no fix is published"`
	Summary      string  `json:"summary,omitempty" jsonschema:"One-line description of the vulnerability"`
}

type componentVulnsOutput struct {
	ComponentID     string            `json:"component_id" jsonschema:"Component these vulnerabilities affect"`
	Vulnerabilities []vulnEntryOutput `json:"vulnerabilities" jsonschema:"Advisories affecting this component, worst first"`
	Total           int64             `json:"total" jsonschema:"Number of advisories returned"`
}

type getVulnerabilityInput struct {
	VulnID string `json:"vuln_id" jsonschema:"CVE or GHSA identifier, e.g. CVE-2024-3094"`
	Limit  int32  `json:"limit,omitempty" jsonschema:"Maximum affected artifacts to return; defaults to 50"`
	Offset int32  `json:"offset,omitempty" jsonschema:"Affected artifacts to skip, for paging"`
}

type affectedArtifactOutput struct {
	ID                string `json:"id" jsonschema:"UUID of the affected artifact"`
	Name              string `json:"name" jsonschema:"Artifact name"`
	Group             string `json:"group,omitempty" jsonschema:"Artifact group"`
	AffectedSBOMCount int64  `json:"affected_sbom_count" jsonschema:"How many of its SBOMs are affected"`
}

type getVulnerabilityOutput struct {
	ID                string                   `json:"id" jsonschema:"Canonical advisory id"`
	Severity          string                   `json:"severity" jsonschema:"critical, high, medium, low or unknown"`
	CvssScore         float64                  `json:"cvss_score,omitempty" jsonschema:"CVSS base score, where the advisory has one"`
	Summary           string                   `json:"summary,omitempty" jsonschema:"One-line description"`
	Details           string                   `json:"details,omitempty" jsonschema:"Full advisory text"`
	Aliases           []string                 `json:"aliases,omitempty" jsonschema:"Other identifiers for the same advisory"`
	AffectedArtifacts []affectedArtifactOutput `json:"affected_artifacts" jsonschema:"Visible artifacts this advisory affects"`
	TotalAffected     int64                    `json:"total_affected_artifacts" jsonschema:"Affected artifacts across all pages"`
}

func registerVulnTools(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_artifact_vulnerabilities",
		Description: "Report the severity histogram for one artifact across all of its SBOMs. This is " +
			"the cheap first question: it says how bad things are without listing anything. To find " +
			"which package is responsible, search its components and call " +
			"ocidex_component_vulnerabilities on the ones you suspect.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in artifactVulnsInput) (*mcp.CallToolResult, artifactVulnsOutput, error) {
		summary, err := api.GetArtifactVulnSummary(ctx, in.ArtifactID)
		if err != nil {
			return nil, artifactVulnsOutput{}, toolError(
				fmt.Sprintf("summarising vulnerabilities for artifact %s", in.ArtifactID), err)
		}
		return nil, artifactVulnsOutput{
			ArtifactID: in.ArtifactID,
			Critical:   summary.Critical,
			High:       summary.High,
			Medium:     summary.Medium,
			Low:        summary.Low,
			Unknown:    summary.Unknown,
			Total:      summary.Total,
		}, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_component_vulnerabilities",
		Description: "List the advisories affecting one component occurrence, with the fixed version " +
			"where one exists. Get the component id from ocidex_search_components. An entry without a " +
			"fixed version has no published fix, which is the case worth reporting rather than " +
			"recommending an upgrade for.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in componentVulnsInput) (*mcp.CallToolResult, componentVulnsOutput, error) {
		vulns, err := api.GetComponentVulns(ctx, in.ComponentID)
		if err != nil {
			return nil, componentVulnsOutput{}, toolError(
				fmt.Sprintf("listing vulnerabilities for component %s", in.ComponentID), err)
		}
		out := componentVulnsOutput{
			ComponentID:     in.ComponentID,
			Vulnerabilities: make([]vulnEntryOutput, 0, len(vulns)),
			Total:           int64(len(vulns)),
		}
		for _, v := range vulns {
			entry := vulnEntryOutput{
				ID:           v.CanonicalId,
				Severity:     v.Severity,
				FixedVersion: deref(v.FixedVersion),
				Summary:      deref(v.Summary),
			}
			if v.CvssScore != nil {
				entry.CvssScore = float64(*v.CvssScore)
			}
			out.Vulnerabilities = append(out.Vulnerabilities, entry)
		}
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_get_vulnerability",
		Description: "Fetch one advisory by CVE or GHSA id and list the visible artifacts it affects. " +
			"Use it to turn an id from the other vulnerability tools into blast radius across the catalog.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in getVulnerabilityInput) (*mcp.CallToolResult, getVulnerabilityOutput, error) {
		limit := in.Limit
		if limit <= 0 {
			limit = defaultSearchLimit
		}
		res, err := api.GetVulnerability(ctx, in.VulnID, client.PageOpts{Limit: limit, Offset: in.Offset})
		if err != nil {
			return nil, getVulnerabilityOutput{}, toolError(fmt.Sprintf("fetching vulnerability %s", in.VulnID), err)
		}

		v := res.Vulnerability
		out := getVulnerabilityOutput{
			ID:                v.CanonicalId,
			Severity:          v.Severity,
			Summary:           deref(v.Summary),
			Details:           deref(v.Details),
			Aliases:           derefSlice(v.Aliases),
			AffectedArtifacts: make([]affectedArtifactOutput, 0),
			TotalAffected:     res.Pagination.Total,
		}
		if v.CvssScore != nil {
			out.CvssScore = float64(*v.CvssScore)
		}
		for _, a := range derefSlice(res.AffectedArtifacts) {
			out.AffectedArtifacts = append(out.AffectedArtifacts, affectedArtifactOutput{
				ID:                a.Id,
				Name:              a.Name,
				Group:             deref(a.Group),
				AffectedSBOMCount: a.AffectedSbomCount,
			})
		}
		return nil, out, nil
	})
}

type ingestSBOMInput struct {
	Bom          string `json:"bom" jsonschema:"The CycloneDX SBOM document as JSON text"`
	Source       string `json:"source" jsonschema:"Ingest channel to attribute this SBOM to: a source UUID or <namespace>/<name>. Its namespace owns the result"`
	Version      string `json:"version,omitempty" jsonschema:"Artifact version or image tag; overrides the value in the document"`
	Architecture string `json:"architecture,omitempty" jsonschema:"Architecture, e.g. amd64"`
	BuildDate    string `json:"build_date,omitempty" jsonschema:"Build date of the image, RFC3339. A container SBOM is rejected without it, alongside version and architecture, unless the document supplies it"`
	SubjectType  string `json:"subject_type,omitempty" jsonschema:"CycloneDX type of the subject, e.g. container or application"`
	SubjectName  string `json:"subject_name,omitempty" jsonschema:"Subject name; takes precedence over the document"`
	SubjectGroup string `json:"subject_group,omitempty" jsonschema:"Subject group, e.g. github.com/pfenerty"`
	SubjectPurl  string `json:"subject_purl,omitempty" jsonschema:"Subject package URL"`
	Digest       string `json:"digest,omitempty" jsonschema:"sha256 of the artifact file itself, not of the SBOM; required for a non-container subject (ADR-040)"`
}

type ingestSBOMOutput struct {
	SBOMID         string `json:"sbom_id" jsonschema:"UUID of the stored SBOM"`
	ComponentCount int64  `json:"component_count" jsonschema:"Components recorded from the document"`
	SpecVersion    string `json:"spec_version" jsonschema:"CycloneDX specification version that was parsed"`
	SerialNumber   string `json:"serial_number,omitempty" jsonschema:"Serial number declared by the document"`
}

// registerIngestTool adds the one tool that writes.
//
// It is annotated non-read-only so a client that gates writes behind
// confirmation can do so, and its description names the scope it needs: an
// agent holding a read-only key should learn that from the description rather
// than from a 403 after uploading a megabyte of JSON.
func registerIngestTool(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_ingest_sbom",
		Description: "Upload a CycloneDX SBOM. This is the only tool that writes, and it needs an API " +
			"key with the read-write scope — a read-only key is rejected. Source is required and " +
			"decides which namespace owns the result. Re-uploading the same artifact digest is " +
			"idempotent rather than duplicating it.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ingestSBOMInput) (*mcp.CallToolResult, ingestSBOMOutput, error) {
		if in.Bom == "" {
			return nil, ingestSBOMOutput{}, errors.New("ingesting an SBOM needs the document itself in bom, as JSON text")
		}
		res, err := api.IngestSBOM(ctx, []byte(in.Bom), client.IngestSbomParams{
			Source:       optional(in.Source),
			Version:      optional(in.Version),
			Architecture: optional(in.Architecture),
			BuildDate:    optional(in.BuildDate),
			SubjectType:  optional(in.SubjectType),
			SubjectName:  optional(in.SubjectName),
			SubjectGroup: optional(in.SubjectGroup),
			SubjectPurl:  optional(in.SubjectPurl),
			Digest:       optional(in.Digest),
		})
		if err != nil {
			// Named separately from toolError's generic scope advice: on the one
			// write in the tool set, "the key is read-only" is the likely cause and
			// re-running login with a read-write key is the fix.
			if errors.Is(err, client.ErrForbidden) {
				return nil, ingestSBOMOutput{}, fmt.Errorf(
					"ingesting the SBOM: %w — this API key cannot write. Ingest needs the `read-write` "+
						"scope; create a key with it and re-run `ocidex-cli login`", err)
			}
			return nil, ingestSBOMOutput{}, toolError("ingesting the SBOM", err)
		}
		return nil, ingestSBOMOutput{
			SBOMID:         res.Id,
			ComponentCount: res.ComponentCount,
			SpecVersion:    res.SpecVersion,
			SerialNumber:   deref(res.SerialNumber),
		}, nil
	})
}

type artifactChangelogInput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the artifact, as returned by ocidex_lookup_artifact"`
	Version    string `json:"version,omitempty" jsonschema:"Only return the entry landing on this version"`
	Arch       string `json:"arch,omitempty" jsonschema:"Restrict the series to one architecture, e.g. amd64"`
	Flavor     string `json:"flavor,omitempty" jsonschema:"Restrict the series to one image flavor (ADR-020)"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum entries to return, newest first; defaults to 20"`
}

// changelogEntryOutput is one version-to-version step. It carries the summary
// counts and the two SBOM ids but not the changes themselves: a changelog spans
// many versions, and inlining every change would make the whole series
// unreadable. The ids are the drill-down into ocidex_diff_sboms.
type changelogEntryOutput struct {
	From    sbomRefOutput       `json:"from" jsonschema:"The SBOM this step compares from"`
	To      sbomRefOutput       `json:"to" jsonschema:"The SBOM this step compares to"`
	Summary changeSummaryOutput `json:"summary" jsonschema:"Change counts for this step; call ocidex_diff_sboms with the two ids for detail"`
}

type artifactChangelogOutput struct {
	ArtifactID    string                 `json:"artifact_id" jsonschema:"Artifact this changelog covers"`
	ResolvedMode  string                 `json:"resolved_mode" jsonschema:"Ordering the server chose: semver where versions allow it, otherwise build-time"`
	Entries       []changelogEntryOutput `json:"entries" jsonschema:"Steps between consecutive versions, newest first"`
	Total         int64                  `json:"total_entries" jsonschema:"Entries before the limit was applied"`
	Architectures []string               `json:"available_architectures,omitempty" jsonschema:"Architectures the series can be restricted to"`
	Flavors       []string               `json:"available_flavors,omitempty" jsonschema:"Flavors the series can be restricted to"`
}

func registerChangelogTool(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_artifact_changelog",
		Description: "Walk an artifact's history as a series of version-to-version steps, each with its " +
			"change counts. Use it to find which release introduced or removed something, then call " +
			"ocidex_diff_sboms with that step's two SBOM ids for the components themselves. A " +
			"multi-architecture or multi-flavor artifact has one series per combination — restrict " +
			"with arch and flavor, whose valid values come back in this tool's own response.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in artifactChangelogInput) (*mcp.CallToolResult, artifactChangelogOutput, error) {
		// The limit goes to the server rather than trimming a full response
		// here (ocidex-7gf7.4). It used to fetch every version-to-version step
		// and keep the first twenty, which for a thousand-version artifact meant
		// the endpoint timed out before this line ever ran.
		limit := in.Limit
		if limit <= 0 {
			limit = defaultRootLimit
		}
		changelog, err := api.GetArtifactChangelog(ctx, in.ArtifactID, client.GetArtifactChangelogParams{
			SubjectVersion: optional(in.Version),
			Arch:           optional(in.Arch),
			Flavor:         optional(in.Flavor),
			Limit:          optionalInt32(limit),
		})
		if err != nil {
			return nil, artifactChangelogOutput{}, toolError(
				fmt.Sprintf("reading the changelog for artifact %s", in.ArtifactID), err)
		}

		entries := derefSlice(changelog.Entries)
		out := artifactChangelogOutput{
			ArtifactID:    changelog.ArtifactId,
			ResolvedMode:  changelog.ResolvedMode,
			Total:         changelog.Pagination.Total,
			Architectures: derefSlice(changelog.AvailableArchitectures),
			Flavors:       derefSlice(changelog.AvailableFlavors),
		}
		out.Entries = make([]changelogEntryOutput, 0, len(entries))
		for _, e := range entries {
			out.Entries = append(out.Entries, changelogEntryOutput{
				From:    toSBOMRefOutput(e.From),
				To:      toSBOMRefOutput(e.To),
				Summary: toChangeSummaryOutput(e.Summary),
			})
		}
		return nil, out, nil
	})
}
