package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// registerInsightTools adds the catalog-wide views: where to start when no
// image or cluster has been named, how to find an artifact without its exact
// name, and how far to trust the answers (license spread, provenance drift and
// the freshness of vulnerability matching).
func registerInsightTools(srv *mcp.Server, api client.Client) {
	registerTopVulnerabilities(srv, api)
	registerSearchArtifacts(srv, api)
	registerLicenseSummary(srv, api)
	registerSBOMDrift(srv, api)
	registerDataFreshness(srv, api)
}

type topVulnsInput struct {
	Mine     bool   `json:"mine,omitempty" jsonschema:"Rank only across namespaces the calling user owns, instead of everything the key can see"`
	Query    string `json:"query,omitempty" jsonschema:"Substring over the advisory id and its aliases, e.g. CVE-2024 or log4"`
	Severity string `json:"severity,omitempty" jsonschema:"Only this severity: critical, high, medium or low (any case)"`
	Sort     string `json:"sort,omitempty" jsonschema:"severity (default, worst first), cvss, sboms (most SBOMs affected), packages, or published (newest first)"`
	Limit    int32  `json:"limit,omitempty" jsonschema:"Maximum advisories to return; defaults to 50"`
	Offset   int32  `json:"offset,omitempty" jsonschema:"Advisories to skip, for paging"`
}

type topVulnOutput struct {
	ID                string   `json:"id" jsonschema:"Canonical advisory id; pass it to ocidex_get_vulnerability or ocidex_vulnerability_workloads"`
	Aliases           []string `json:"aliases,omitempty"`
	Severity          string   `json:"severity"`
	CvssScore         float64  `json:"cvss_score,omitempty"`
	Summary           string   `json:"summary,omitempty"`
	AffectedSBOMCount int64    `json:"affected_sbom_count" jsonschema:"SBOMs carrying it: the breadth of the fix"`
	AffectedPurlCount int64    `json:"affected_package_count" jsonschema:"Distinct package versions it matches"`
	PublishedAt       string   `json:"published_at,omitempty"`
}

type topVulnsOutput struct {
	Scope           string          `json:"scope" jsonschema:"catalog or mine"`
	Vulnerabilities []topVulnOutput `json:"vulnerabilities"`
	Total           int64           `json:"total"`
	Limit           int32           `json:"limit"`
	Offset          int32           `json:"offset"`
	NextOffset      int32           `json:"next_offset,omitempty" jsonschema:"Pass as offset to get the next page; absent on the last page"`
}

// topVulnSorts maps the tool's sort names onto the API's columns.
// Every ranking reads best descending, so only the column varies.
var topVulnSorts = map[string]string{
	"severity":  "severity",
	"cvss":      "cvssScore",
	"sboms":     "affectedSbomCount",
	"packages":  "affectedPurlCount",
	"published": "publishedAt",
}

const sortDescending = "desc"

func registerTopVulnerabilities(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_top_vulnerabilities",
		Description: "Rank vulnerabilities across the whole catalog (or, with mine, across your own namespaces), " +
			"each with how many SBOMs and packages it affects. This is the starting point when no image or " +
			"cluster is named: \"what should we fix first\". Sort by sboms for the widest-reaching fix. " +
			"Follow a row with ocidex_get_vulnerability for affected artifacts, or " +
			"ocidex_vulnerability_workloads for what is running it.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in topVulnsInput) (*mcp.CallToolResult, topVulnsOutput, error) {
		if in.Severity != "" && severityRank(in.Severity) == severityRank("unknown") {
			return nil, topVulnsOutput{}, fmt.Errorf("severity %q is not one of critical, high, medium, low", in.Severity)
		}
		sortSpec := topVulnSorts["severity"]
		if in.Sort != "" {
			s, ok := topVulnSorts[in.Sort]
			if !ok {
				return nil, topVulnsOutput{}, fmt.Errorf("sort %q is not severity, cvss, sboms, packages or published", in.Sort)
			}
			sortSpec = s
		}
		limit := optionalInt32(int(pageLimit(in.Limit, defaultSearchLimit)))
		offset := optionalInt32(int(in.Offset))

		var (
			page  client.Page[client.TopVulnEntry]
			err   error
			scope = "catalog"
		)
		if in.Mine {
			scope = "mine"
			sev, perr := severityParam[client.ListMyVulnerabilitiesParamsSeverity](in.Severity)
			if perr != nil {
				return nil, topVulnsOutput{}, perr
			}
			s, d := client.ListMyVulnerabilitiesParamsSort(sortSpec), client.ListMyVulnerabilitiesParamsSortDir(sortDescending)
			page, err = api.ListMyVulnerabilities(ctx, client.ListMyVulnerabilitiesParams{
				Q: optional(in.Query), Severity: sev, Sort: &s, SortDir: &d, Limit: limit, Offset: offset,
			})
		} else {
			sev, perr := severityParam[client.ListTopVulnerabilitiesParamsSeverity](in.Severity)
			if perr != nil {
				return nil, topVulnsOutput{}, perr
			}
			s, d := client.ListTopVulnerabilitiesParamsSort(sortSpec), client.ListTopVulnerabilitiesParamsSortDir(sortDescending)
			page, err = api.ListTopVulnerabilities(ctx, client.ListTopVulnerabilitiesParams{
				Q: optional(in.Query), Severity: sev, Sort: &s, SortDir: &d, Limit: limit, Offset: offset,
			})
		}
		if err != nil {
			return nil, topVulnsOutput{}, toolError("ranking vulnerabilities", err)
		}
		out := topVulnsOutput{
			Scope:           scope,
			Vulnerabilities: make([]topVulnOutput, 0, len(page.Data)),
			Total:           page.Pagination.Total,
			Limit:           page.Pagination.Limit,
			Offset:          page.Pagination.Offset,
		}
		for _, v := range page.Data {
			row := topVulnOutput{
				ID:                v.CanonicalId,
				Aliases:           derefSlice(v.Aliases),
				Severity:          v.Severity,
				CvssScore:         float32Value(v.CvssScore),
				Summary:           deref(v.Summary),
				AffectedSBOMCount: v.AffectedSbomCount,
				AffectedPurlCount: v.AffectedPurlCount,
			}
			if v.PublishedAt != nil {
				row.PublishedAt = v.PublishedAt.UTC().Format("2006-01-02T15:04:05Z")
			}
			out.Vulnerabilities = append(out.Vulnerabilities, row)
		}
		return nil, out, nil
	})
}

type searchArtifactsInput struct {
	Name                string `json:"name" jsonschema:"Text the artifact name contains, case-insensitive, e.g. redis"`
	Type                string `json:"type,omitempty" jsonschema:"CycloneDX type, e.g. container or application"`
	IncludeInsufficient bool   `json:"include_insufficient,omitempty" jsonschema:"Also return artifacts whose SBOMs are too thin to trust for vulnerability answers"`
	Limit               int32  `json:"limit,omitempty" jsonschema:"Maximum artifacts to return; defaults to 50"`
}

type artifactSummaryOutput struct {
	ID            string `json:"id" jsonschema:"UUID; pass to tools that take an artifact id"`
	Name          string `json:"name" jsonschema:"Exact name; pass to ocidex_lookup_artifact or ocidex_lookup_sbom"`
	Type          string `json:"type"`
	Group         string `json:"group,omitempty"`
	SBOMCount     int64  `json:"sbom_count"`
	SigningStatus string `json:"signing_status"`
	Critical      int64  `json:"critical"`
	High          int64  `json:"high"`
	VulnTotal     int64  `json:"vuln_total" jsonschema:"Vulnerabilities in the latest version"`
}

type searchArtifactsOutput struct {
	Artifacts []artifactSummaryOutput `json:"artifacts"`
	HasMore   bool                    `json:"has_more" jsonschema:"More artifacts match; narrow the name rather than paging"`
}

func registerSearchArtifacts(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_search_artifacts",
		Description: "Find artifacts whose name contains some text, with their latest severity counts. Use it " +
			"when you do not know an artifact's exact name (ocidex_lookup_artifact needs it exact), or to " +
			"list every image in a family, e.g. everything under ghcr.io/acme.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in searchArtifactsInput) (*mcp.CallToolResult, searchArtifactsOutput, error) {
		if in.Name == "" {
			return nil, searchArtifactsOutput{}, fmt.Errorf("searching artifacts needs some name text; call ocidex_list_namespaces to see what is visible")
		}
		page, err := api.ListArtifacts(ctx, client.ArtifactFilter{
			Name: in.Name, Type: in.Type, IncludeInsufficient: in.IncludeInsufficient,
		}, client.PageOpts{Limit: pageLimit(in.Limit, defaultSearchLimit)})
		if err != nil {
			return nil, searchArtifactsOutput{}, toolError(fmt.Sprintf("searching artifacts for %q", in.Name), err)
		}
		out := searchArtifactsOutput{
			Artifacts: make([]artifactSummaryOutput, 0, len(page.Data)),
			HasMore:   page.Pagination.HasMore,
		}
		for _, a := range page.Data {
			row := artifactSummaryOutput{
				ID: a.Id, Name: a.Name, Type: a.Type, Group: deref(a.Group),
				SBOMCount: a.SbomCount, SigningStatus: a.SigningStatus,
			}
			if a.Vulns != nil {
				row.Critical, row.High, row.VulnTotal = a.Vulns.Critical, a.Vulns.High, a.Vulns.Total
			}
			out.Artifacts = append(out.Artifacts, row)
		}
		return nil, out, nil
	})
}

type licenseSummaryInput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the artifact, as returned by ocidex_lookup_artifact"`
}

type licenseSummaryOutput struct {
	ArtifactID string          `json:"artifact_id"`
	SBOMID     string          `json:"sbom_id,omitempty" jsonschema:"SBOM the counts come from: the most recently ingested"`
	Version    string          `json:"version,omitempty"`
	IngestedAt string          `json:"ingested_at,omitempty"`
	Licenses   []licenseOutput `json:"licenses" jsonschema:"Licenses in that SBOM, most components first"`
}

func registerLicenseSummary(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_artifact_license_summary",
		Description: "Count the licenses carried by an artifact's most recent SBOM, with each license's category " +
			"(permissive, copyleft, ...). Use it for license compliance questions, and to check that a " +
			"replacement package or base image does not introduce a copyleft license.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in licenseSummaryInput) (*mcp.CallToolResult, licenseSummaryOutput, error) {
		res, err := api.GetArtifactLicenseSummary(ctx, in.ArtifactID)
		if err != nil {
			return nil, licenseSummaryOutput{}, toolError(fmt.Sprintf("summarising licenses for artifact %s", in.ArtifactID), err)
		}
		out := licenseSummaryOutput{
			ArtifactID: in.ArtifactID,
			SBOMID:     deref(res.SbomId),
			Version:    deref(res.SubjectVersion),
			Licenses:   make([]licenseOutput, 0, len(derefSlice(res.Licenses))),
		}
		if res.SbomCreatedAt != nil {
			out.IngestedAt = res.SbomCreatedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		for _, l := range derefSlice(res.Licenses) {
			out.Licenses = append(out.Licenses, licenseOutput{
				ID: l.Id, SpdxID: deref(l.SpdxId), Name: l.Name, Category: l.Category,
				ComponentCount: l.ComponentCount, URL: deref(l.Url),
			})
		}
		sort.SliceStable(out.Licenses, func(i, j int) bool {
			return out.Licenses[i].ComponentCount > out.Licenses[j].ComponentCount
		})
		return nil, out, nil
	})
}

type sbomDriftInput struct {
	SBOMID string `json:"sbom_id" jsonschema:"UUID of the SBOM"`
	Limit  int32  `json:"limit,omitempty" jsonschema:"Maximum events to return; defaults to 20"`
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call, for the next page"`
}

type driftEventOutput struct {
	DetectedAt     string `json:"detected_at"`
	PreviousStatus string `json:"previous_status"`
	NewStatus      string `json:"new_status"`
	Reason         string `json:"reason"`
}

type sbomDriftOutput struct {
	SBOMID     string             `json:"sbom_id"`
	Events     []driftEventOutput `json:"events" jsonschema:"Changes to the SBOM's signing or provenance status, newest first"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

func registerSBOMDrift(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_sbom_drift",
		Description: "List the provenance drift recorded for one SBOM: each time its signature or attestation " +
			"status changed, and why. Use it when signing_status looks wrong, or before trusting an " +
			"image whose provenance used to verify and no longer does.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sbomDriftInput) (*mcp.CallToolResult, sbomDriftOutput, error) {
		page, err := api.ListSBOMDriftHistory(ctx, in.SBOMID, client.ListSbomDriftHistoryParams{
			Limit:  optionalInt32(int(pageLimit(in.Limit, defaultRootLimit))),
			Cursor: optional(in.Cursor),
		})
		if err != nil {
			return nil, sbomDriftOutput{}, toolError(fmt.Sprintf("listing provenance drift for SBOM %s", in.SBOMID), err)
		}
		out := sbomDriftOutput{
			SBOMID:     in.SBOMID,
			Events:     make([]driftEventOutput, 0, len(page.Data)),
			NextCursor: deref(page.Pagination.NextCursor),
		}
		for _, d := range page.Data {
			out.Events = append(out.Events, driftEventOutput{
				DetectedAt:     d.DetectedAt.UTC().Format("2006-01-02T15:04:05Z"),
				PreviousStatus: d.PreviousStatus,
				NewStatus:      d.NewStatus,
				Reason:         d.Reason,
			})
		}
		return nil, out, nil
	})
}

type dataFreshnessInput struct{}

type enricherStateOutput struct {
	Enricher string           `json:"enricher" jsonschema:"Enricher name, e.g. the vulnerability matcher"`
	States   map[string]int64 `json:"states" jsonschema:"Job counts per state, queued, running, succeeded, failed or pruned"`
	Backlog  int64            `json:"backlog" jsonschema:"Queued or running jobs: SBOMs whose answers from this enricher are not current"`
	Failed   int64            `json:"failed"`
}

type dataFreshnessOutput struct {
	Enrichers []enricherStateOutput `json:"enrichers"`
	Current   bool                  `json:"current" jsonschema:"No enricher has a backlog or failures, so vulnerability and provenance answers reflect every ingested SBOM"`
}

func registerDataFreshness(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_data_freshness",
		Description: "Report whether OCIDex's enrichment (vulnerability matching, provenance checks) has caught up " +
			"with every ingested SBOM. Call it before stating that something is clean or fixed: a backlog " +
			"or failures mean some vulnerability counts are stale or missing. For one version, " +
			"ocidex_list_artifact_versions also reports when its SBOM was ingested.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ dataFreshnessInput) (*mcp.CallToolResult, dataFreshnessOutput, error) {
		rows, err := api.GetEnrichmentJobsSummary(ctx)
		if err != nil {
			return nil, dataFreshnessOutput{}, toolError("reading enrichment status", err)
		}
		byName := map[string]*enricherStateOutput{}
		var names []string
		for _, r := range rows {
			e, ok := byName[r.EnricherName]
			if !ok {
				e = &enricherStateOutput{Enricher: r.EnricherName, States: map[string]int64{}}
				byName[r.EnricherName] = e
				names = append(names, r.EnricherName)
			}
			e.States[r.State] += r.Count
			switch r.State {
			case "queued", "running":
				e.Backlog += r.Count
			case "failed":
				e.Failed += r.Count
			}
		}
		sort.Strings(names)
		out := dataFreshnessOutput{Enrichers: make([]enricherStateOutput, 0, len(names)), Current: true}
		for _, n := range names {
			e := byName[n]
			if e.Backlog > 0 || e.Failed > 0 {
				out.Current = false
			}
			out.Enrichers = append(out.Enrichers, *e)
		}
		return nil, out, nil
	})
}
