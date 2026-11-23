package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// maxAPIPage is the largest page the list endpoints accept. Tools that must see
// a whole result to aggregate it page at this size.
const maxAPIPage = 200

// packageRollupCap bounds how many findings ocidex_sbom_findings will page
// through to build its per-package view. An image with more findings than this
// is rare, and the output says when it happened rather than silently rolling up
// a prefix.
const packageRollupCap = 2000

// severityOrder ranks severities worst first. The API spells them in either
// case depending on the endpoint, so lookups go through severityRank.
var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

func severityRank(s string) int {
	if r, ok := severityOrder[strings.ToLower(s)]; ok {
		return r
	}
	return len(severityOrder)
}

// severityParam converts a model-supplied severity into the uppercase enum the
// list endpoints take. It is lenient about case, because models write
// "critical" as often as "CRITICAL", and strict about the value, because the
// server answers an unknown one with a 422 that names the field but not the
// choices.
func severityParam[T ~string](s string) (*T, error) {
	if s == "" {
		return nil, nil
	}
	if _, ok := severityOrder[strings.ToLower(s)]; !ok {
		return nil, fmt.Errorf("severity %q is not one of critical, high, medium, low, unknown", s)
	}
	v := T(strings.ToUpper(s))
	return &v, nil
}

// pageLimit applies a tool's default page size and the API ceiling to a
// model-supplied limit.
func pageLimit(limit int32, def int32) int32 {
	switch {
	case limit <= 0:
		return def
	case limit > maxAPIPage:
		return maxAPIPage
	default:
		return limit
	}
}

func float32Value(v *float32) float64 {
	if v == nil {
		return 0
	}
	return float64(*v)
}

// registerRemediationTools adds the tools that turn "this image is vulnerable"
// into "upgrade these packages to these versions": findings with fixed
// versions, the versions and components to anchor them to, the base-image
// lineage that decides whether a rebuild is the fix, and where else a fixed
// version already ships.
func registerRemediationTools(srv *mcp.Server, api client.Client) {
	registerFindingsTools(srv, api)
	registerArtifactHistoryTools(srv, api)
	registerSBOMComponentsTool(srv, api)
	registerLineageTool(srv, api)
	registerComponentVersionsTool(srv, api)
}

type affectedVersionOutput struct {
	Version              string   `json:"version" jsonschema:"Artifact version"`
	SBOMID               string   `json:"sbom_id" jsonschema:"Newest SBOM of that version; pass it to ocidex_sbom_findings for fixed versions"`
	AffectedPackageCount int64    `json:"affected_package_count" jsonschema:"Packages in that version the advisory matches"`
	PackageNames         []string `json:"package_names,omitempty" jsonschema:"Names of those packages"`
}

type artifactFindingOutput struct {
	ID                   string                  `json:"id" jsonschema:"Canonical advisory id; pass it to ocidex_get_vulnerability"`
	Severity             string                  `json:"severity"`
	CvssScore            float64                 `json:"cvss_score,omitempty"`
	Summary              string                  `json:"summary,omitempty"`
	AffectedVersionCount int64                   `json:"affected_version_count" jsonschema:"How many of the scanned versions carry it"`
	AffectedPackageCount int64                   `json:"affected_package_count" jsonschema:"Distinct packages it matches across those versions"`
	AffectedVersions     []affectedVersionOutput `json:"affected_versions" jsonschema:"The versions it affects, each with the SBOM to drill into"`
}

type artifactFindingsInput struct {
	ArtifactID   string `json:"artifact_id" jsonschema:"UUID of the artifact, as returned by ocidex_lookup_artifact"`
	Severity     string `json:"severity,omitempty" jsonschema:"Only this severity: critical, high, medium, low or unknown (any case)"`
	VulnID       string `json:"vuln_id,omitempty" jsonschema:"Only this advisory, by canonical id or alias"`
	VersionScope int32  `json:"version_scope,omitempty" jsonschema:"How many of the most recent versions to scan, 1-200; the server defaults to 20. Use 1 for the latest version only"`
	Limit        int32  `json:"limit,omitempty" jsonschema:"Maximum findings to return; defaults to 50"`
	Offset       int32  `json:"offset,omitempty" jsonschema:"Findings to skip, for paging"`
}

type artifactFindingsOutput struct {
	ArtifactID    string                  `json:"artifact_id"`
	Findings      []artifactFindingOutput `json:"findings" jsonschema:"Advisories, worst first, one row per alias group"`
	Total         int64                   `json:"total" jsonschema:"Findings across all pages"`
	Limit         int32                   `json:"limit"`
	Offset        int32                   `json:"offset"`
	VersionScope  int32                   `json:"version_scope" jsonschema:"Versions that were scanned"`
	TotalVersions int64                   `json:"total_versions" jsonschema:"Versions the artifact has; more than version_scope means older ones were not considered"`
}

type fixPackageOutput struct {
	Name             string `json:"name"`
	Group            string `json:"group,omitempty"`
	Version          string `json:"version,omitempty" jsonschema:"Installed version"`
	Purl             string `json:"purl"`
	FixedVersion     string `json:"fixed_version,omitempty" jsonschema:"Version that fixes it; absent when no fix is published"`
	FixState         string `json:"fix_state,omitempty" jsonschema:"fixed, not-fixed, wont-fix or unknown. wont-fix means the distro decided not to fix it, so an upgrade will not help"`
	MatchedViaSource bool   `json:"matched_via_source,omitempty" jsonschema:"Matched through the source package rather than the binary; the fix arrives with the source package's update"`
}

type sbomFindingOutput struct {
	ID               string             `json:"id" jsonschema:"Canonical advisory id"`
	Severity         string             `json:"severity"`
	CvssScore        float64            `json:"cvss_score,omitempty"`
	Summary          string             `json:"summary,omitempty"`
	AffectedPackages []fixPackageOutput `json:"affected_packages" jsonschema:"The packages it matches, each with its fixed version and fix state"`
}

// packageRollupOutput is one package's share of an SBOM's findings: the unit a
// remediation plan is written in, since one upgrade usually clears several
// advisories at once.
type packageRollupOutput struct {
	Name           string   `json:"name"`
	Group          string   `json:"group,omitempty"`
	Version        string   `json:"version,omitempty" jsonschema:"Installed version"`
	Purl           string   `json:"purl"`
	WorstSeverity  string   `json:"worst_severity"`
	AdvisoryCount  int      `json:"advisory_count" jsonschema:"Advisories matching this package"`
	FixedVersions  []string `json:"fixed_versions,omitempty" jsonschema:"Distinct fixed versions named by those advisories; upgrading to the highest clears every fixable one"`
	UnfixedCount   int      `json:"unfixed_count" jsonschema:"Advisories with no fixed version: report these, an upgrade will not clear them"`
	WontFixCount   int      `json:"wont_fix_count,omitempty" jsonschema:"Advisories the distro marked wont-fix"`
	AdvisoryIDs    []string `json:"advisory_ids" jsonschema:"The advisories, worst first"`
	ViaSourceMatch bool     `json:"matched_via_source,omitempty" jsonschema:"At least one advisory matched through the source package"`
}

type sbomFindingsInput struct {
	SBOMID   string `json:"sbom_id" jsonschema:"UUID of the SBOM, from ocidex_lookup_sbom, ocidex_list_artifact_versions or ocidex_cluster_images"`
	GroupBy  string `json:"group_by,omitempty" jsonschema:"finding (default): one row per advisory. package: one row per vulnerable package with the fixed versions that clear it, which is the shape a remediation plan needs"`
	Severity string `json:"severity,omitempty" jsonschema:"Only this severity: critical, high, medium, low or unknown (any case)"`
	Limit    int32  `json:"limit,omitempty" jsonschema:"Maximum rows to return; defaults to 50"`
	Offset   int32  `json:"offset,omitempty" jsonschema:"Rows to skip, for paging"`
}

type sbomFindingsOutput struct {
	SBOMID    string                `json:"sbom_id"`
	GroupBy   string                `json:"group_by"`
	Findings  []sbomFindingOutput   `json:"findings,omitempty" jsonschema:"Present when group_by is finding: advisories, worst first"`
	Packages  []packageRollupOutput `json:"packages,omitempty" jsonschema:"Present when group_by is package: vulnerable packages, worst first, then by advisory count"`
	Total     int64                 `json:"total" jsonschema:"Rows across all pages, in the chosen grouping"`
	Limit     int32                 `json:"limit"`
	Offset    int32                 `json:"offset"`
	Truncated bool                  `json:"truncated,omitempty" jsonschema:"The package rollup stopped at its cap and covers only the worst findings"`
}

func toFixPackages(pkgs []client.SBOMVulnPackage) []fixPackageOutput {
	out := make([]fixPackageOutput, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, fixPackageOutput{
			Name:             p.Name,
			Group:            deref(p.Group),
			Version:          deref(p.Version),
			Purl:             p.Purl,
			FixedVersion:     deref(p.FixedVersion),
			FixState:         deref(p.FixState),
			MatchedViaSource: p.MatchedViaSource,
		})
	}
	return out
}

func registerFindingsTools(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_artifact_findings",
		Description: "List an artifact's vulnerabilities across its recent versions, worst first, each with " +
			"the versions it affects and the SBOM id of each. Use it to see which advisories persist into " +
			"the latest release and which an upgrade of the artifact itself already cleared. For the " +
			"packages and fixed versions behind a finding, pass a version's sbom_id to ocidex_sbom_findings.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in artifactFindingsInput) (*mcp.CallToolResult, artifactFindingsOutput, error) {
		sev, err := severityParam[client.ListArtifactVulnsParamsSeverity](in.Severity)
		if err != nil {
			return nil, artifactFindingsOutput{}, err
		}
		params := client.ListArtifactVulnsParams{
			Severity: sev,
			Vuln:     optional(in.VulnID),
			Limit:    optionalInt32(int(pageLimit(in.Limit, defaultSearchLimit))),
			Offset:   optionalInt32(int(in.Offset)),
		}
		if in.VersionScope > 0 {
			params.VersionScope = optionalInt32(int(in.VersionScope))
		}
		res, err := api.ListArtifactVulns(ctx, in.ArtifactID, params)
		if err != nil {
			return nil, artifactFindingsOutput{}, toolError(fmt.Sprintf("listing findings for artifact %s", in.ArtifactID), err)
		}
		out := artifactFindingsOutput{
			ArtifactID:    in.ArtifactID,
			Findings:      make([]artifactFindingOutput, 0, len(derefSlice(res.Data))),
			Total:         res.Pagination.Total,
			Limit:         res.Pagination.Limit,
			Offset:        res.Pagination.Offset,
			VersionScope:  res.VersionScope,
			TotalVersions: res.TotalVersions,
		}
		for _, f := range derefSlice(res.Data) {
			row := artifactFindingOutput{
				ID:                   f.CanonicalId,
				Severity:             f.Severity,
				CvssScore:            float32Value(f.CvssScore),
				Summary:              deref(f.Summary),
				AffectedVersionCount: f.AffectedVersionCount,
				AffectedPackageCount: f.AffectedPackageCount,
				AffectedVersions:     make([]affectedVersionOutput, 0, len(derefSlice(f.AffectedVersions))),
			}
			for _, v := range derefSlice(f.AffectedVersions) {
				row.AffectedVersions = append(row.AffectedVersions, affectedVersionOutput{
					Version:              v.Version,
					SBOMID:               v.SbomId,
					AffectedPackageCount: v.AffectedPackageCount,
					PackageNames:         derefSlice(v.PackageNames),
				})
			}
			out.Findings = append(out.Findings, row)
		}
		return nil, out, nil
	})

	addTool(srv, &mcp.Tool{
		Name: "ocidex_sbom_findings",
		Description: "List one SBOM's vulnerabilities with the affected packages, their fixed versions and " +
			"fix state. This is the tool for writing a remediation plan for one image build. Set " +
			"group_by to package to get one row per vulnerable package with the fixed versions that " +
			"clear it, which shows which single upgrade clears the most advisories. A package whose " +
			"advisories are all unfixed or wont-fix cannot be upgraded away: report it, or look for a " +
			"different base image with ocidex_artifact_lineage.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in sbomFindingsInput) (*mcp.CallToolResult, sbomFindingsOutput, error) {
		sev, err := severityParam[client.ListSbomVulnsParamsSeverity](in.Severity)
		if err != nil {
			return nil, sbomFindingsOutput{}, err
		}
		limit := pageLimit(in.Limit, defaultSearchLimit)
		switch in.GroupBy {
		case "", "finding":
			page, err := api.ListSBOMVulns(ctx, in.SBOMID, client.ListSbomVulnsParams{
				Severity: sev,
				Limit:    optionalInt32(int(limit)),
				Offset:   optionalInt32(int(in.Offset)),
			})
			if err != nil {
				return nil, sbomFindingsOutput{}, toolError(fmt.Sprintf("listing findings for SBOM %s", in.SBOMID), err)
			}
			out := sbomFindingsOutput{
				SBOMID:   in.SBOMID,
				GroupBy:  "finding",
				Findings: make([]sbomFindingOutput, 0, len(page.Data)),
				Total:    page.Pagination.Total,
				Limit:    page.Pagination.Limit,
				Offset:   page.Pagination.Offset,
			}
			for _, f := range page.Data {
				out.Findings = append(out.Findings, sbomFindingOutput{
					ID:               f.CanonicalId,
					Severity:         f.Severity,
					CvssScore:        float32Value(f.CvssScore),
					Summary:          deref(f.Summary),
					AffectedPackages: toFixPackages(derefSlice(f.AffectedPackages)),
				})
			}
			return nil, out, nil
		case "package":
			findings, truncated, err := allSBOMFindings(ctx, api, in.SBOMID, sev)
			if err != nil {
				return nil, sbomFindingsOutput{}, toolError(fmt.Sprintf("listing findings for SBOM %s", in.SBOMID), err)
			}
			rollup := rollupByPackage(findings)
			out := sbomFindingsOutput{
				SBOMID:    in.SBOMID,
				GroupBy:   "package",
				Packages:  pageSlice(rollup, int(in.Offset), int(limit)),
				Total:     int64(len(rollup)),
				Limit:     limit,
				Offset:    in.Offset,
				Truncated: truncated,
			}
			return nil, out, nil
		default:
			return nil, sbomFindingsOutput{}, fmt.Errorf("group_by %q is not finding or package", in.GroupBy)
		}
	})
}

// allSBOMFindings pages through an SBOM's findings, worst first, up to
// packageRollupCap. The cap applies to findings, not packages, and the worst
// findings come first, so a truncated rollup is still the part that matters.
func allSBOMFindings(ctx context.Context, api client.Client, sbomID string, sev *client.ListSbomVulnsParamsSeverity) ([]client.SBOMVulnEntry, bool, error) {
	var all []client.SBOMVulnEntry
	for offset := 0; ; {
		page, err := api.ListSBOMVulns(ctx, sbomID, client.ListSbomVulnsParams{
			Severity: sev,
			Limit:    optionalInt32(maxAPIPage),
			Offset:   optionalInt32(offset),
		})
		if err != nil {
			return nil, false, err
		}
		all = append(all, page.Data...)
		offset += len(page.Data)
		if len(page.Data) == 0 || int64(offset) >= page.Pagination.Total {
			return all, false, nil
		}
		if len(all) >= packageRollupCap {
			return all, true, nil
		}
	}
}

// rollupByPackage regroups findings by the package they hit. The key is the
// purl plus installed version, because the same purl at two versions in one
// SBOM (vendored copies) needs two upgrades.
func rollupByPackage(findings []client.SBOMVulnEntry) []packageRollupOutput {
	type acc struct {
		row   packageRollupOutput
		fixed map[string]bool
	}
	byKey := map[string]*acc{}
	var order []string
	for _, f := range findings {
		for _, p := range derefSlice(f.AffectedPackages) {
			key := p.Purl + "@" + deref(p.Version)
			a, ok := byKey[key]
			if !ok {
				a = &acc{
					row: packageRollupOutput{
						Name:          p.Name,
						Group:         deref(p.Group),
						Version:       deref(p.Version),
						Purl:          p.Purl,
						WorstSeverity: f.Severity,
					},
					fixed: map[string]bool{},
				}
				byKey[key] = a
				order = append(order, key)
			}
			a.row.AdvisoryCount++
			a.row.AdvisoryIDs = append(a.row.AdvisoryIDs, f.CanonicalId)
			if severityRank(f.Severity) < severityRank(a.row.WorstSeverity) {
				a.row.WorstSeverity = f.Severity
			}
			if fv := deref(p.FixedVersion); fv != "" {
				if !a.fixed[fv] {
					a.fixed[fv] = true
					a.row.FixedVersions = append(a.row.FixedVersions, fv)
				}
			} else {
				a.row.UnfixedCount++
			}
			if deref(p.FixState) == "wont-fix" {
				a.row.WontFixCount++
			}
			if p.MatchedViaSource {
				a.row.ViaSourceMatch = true
			}
		}
	}
	out := make([]packageRollupOutput, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k].row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank(out[i].WorstSeverity), severityRank(out[j].WorstSeverity)
		if ri != rj {
			return ri < rj
		}
		return out[i].AdvisoryCount > out[j].AdvisoryCount
	})
	return out
}

// pageSlice applies offset and limit to a slice the tool assembled itself.
// It always returns a non-nil slice so an empty page serialises as [].
func pageSlice[T any](rows []T, offset, limit int) []T {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(rows) {
		return []T{}
	}
	end := offset + limit
	if limit <= 0 || end > len(rows) {
		end = len(rows)
	}
	return rows[offset:end]
}

type artifactVersionOutput struct {
	Version       string   `json:"version" jsonschema:"Version label; pass it with the artifact name to ocidex_lookup_sbom"`
	SBOMID        string   `json:"sbom_id" jsonschema:"Newest SBOM recorded for this version"`
	Architectures []string `json:"architectures,omitempty" jsonschema:"Architectures recorded; more than one means one SBOM each"`
	BuildDate     string   `json:"build_date,omitempty"`
	CreatedAt     string   `json:"ingested_at" jsonschema:"When OCIDex recorded the SBOM; the freshness of every answer about this version"`
	SBOMCount     int64    `json:"sbom_count"`
	Sufficient    bool     `json:"sufficient" jsonschema:"Whether the SBOM is complete enough to trust for vulnerability answers"`
	SigningStatus string   `json:"signing_status"`
	SourceURL     string   `json:"source_url,omitempty" jsonschema:"Source repository the version was built from"`
	Revision      string   `json:"revision,omitempty" jsonschema:"Source revision the version was built from"`
	Critical      int64    `json:"critical"`
	High          int64    `json:"high"`
	Medium        int64    `json:"medium"`
	Low           int64    `json:"low"`
	VulnTotal     int64    `json:"vuln_total"`
}

type listArtifactVersionsInput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the artifact, as returned by ocidex_lookup_artifact"`
	Limit      int32  `json:"limit,omitempty" jsonschema:"Maximum versions to return; defaults to 20"`
	Offset     int32  `json:"offset,omitempty" jsonschema:"Versions to skip, for paging"`
}

type listArtifactVersionsOutput struct {
	ArtifactID string                  `json:"artifact_id"`
	Versions   []artifactVersionOutput `json:"versions" jsonschema:"Versions, newest first, each with its severity counts"`
	Total      int64                   `json:"total"`
	Limit      int32                   `json:"limit"`
	Offset     int32                   `json:"offset"`
}

func registerArtifactHistoryTools(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_list_artifact_versions",
		Description: "List an artifact's versions, newest first, each with its newest SBOM id, severity " +
			"counts, build date and source revision. Use it to find the latest version (the one a " +
			"remediation plan targets), to see whether a newer release already fixed things, and to get " +
			"an sbom_id for ocidex_sbom_findings without guessing a version string.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listArtifactVersionsInput) (*mcp.CallToolResult, listArtifactVersionsOutput, error) {
		page, err := api.ListArtifactVersions(ctx, in.ArtifactID, client.PageOpts{
			Limit:  pageLimit(in.Limit, defaultRootLimit),
			Offset: in.Offset,
		})
		if err != nil {
			return nil, listArtifactVersionsOutput{}, toolError(fmt.Sprintf("listing versions of artifact %s", in.ArtifactID), err)
		}
		out := listArtifactVersionsOutput{
			ArtifactID: in.ArtifactID,
			Versions:   make([]artifactVersionOutput, 0, len(page.Data)),
			Total:      page.Pagination.Total,
			Limit:      page.Pagination.Limit,
			Offset:     page.Pagination.Offset,
		}
		for _, v := range page.Data {
			row := artifactVersionOutput{
				Version:       deref(v.ImageVersion),
				SBOMID:        v.SbomId,
				Architectures: derefSlice(v.Architectures),
				CreatedAt:     v.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
				SBOMCount:     v.SbomCount,
				Sufficient:    v.Sufficient,
				SigningStatus: string(v.SigningStatus),
				SourceURL:     deref(v.SourceUrl),
				Revision:      deref(v.Revision),
			}
			if row.Version == "" {
				row.Version = v.VersionKey
			}
			if v.BuildDate != nil {
				row.BuildDate = v.BuildDate.UTC().Format("2006-01-02T15:04:05Z")
			}
			if v.Vulns != nil {
				row.Critical, row.High, row.Medium, row.Low, row.VulnTotal =
					v.Vulns.Critical, v.Vulns.High, v.Vulns.Medium, v.Vulns.Low, v.Vulns.Total
			}
			out.Versions = append(out.Versions, row)
		}
		return nil, out, nil
	})
}

type listSBOMComponentsInput struct {
	SBOMID         string `json:"sbom_id" jsonschema:"UUID of the SBOM"`
	VulnerableOnly bool   `json:"vulnerable_only,omitempty" jsonschema:"Only components with at least one known vulnerability, worst first"`
	DirectOnly     bool   `json:"direct_only,omitempty" jsonschema:"Only direct dependencies of the artifact"`
	Name           string `json:"name,omitempty" jsonschema:"Only components whose name contains this text (case-insensitive)"`
	Limit          int32  `json:"limit,omitempty" jsonschema:"Maximum components to return; defaults to 50"`
	Offset         int32  `json:"offset,omitempty" jsonschema:"Components to skip, for paging"`
}

type listSBOMComponentsOutput struct {
	SBOMID     string            `json:"sbom_id"`
	Components []componentOutput `json:"components"`
	Total      int64             `json:"total" jsonschema:"Components matching the filters, across all pages"`
	Limit      int32             `json:"limit"`
	Offset     int32             `json:"offset"`
}

func registerSBOMComponentsTool(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_list_sbom_components",
		Description: "List the components inside one SBOM, optionally only the vulnerable or direct ones. " +
			"Each row's id goes to ocidex_component_vulnerabilities. Use it to inventory an image, or " +
			"to tell a direct dependency (bump it in your manifest) from a transitive one (bump whatever " +
			"pulls it in, found with ocidex_diff_tree).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listSBOMComponentsInput) (*mcp.CallToolResult, listSBOMComponentsOutput, error) {
		// The endpoint returns the whole SBOM unpaged, so filtering and paging
		// happen here rather than shipping thousands of rows to the model.
		all, err := api.ListSBOMComponents(ctx, in.SBOMID)
		if err != nil {
			return nil, listSBOMComponentsOutput{}, toolError(fmt.Sprintf("listing components of SBOM %s", in.SBOMID), err)
		}
		name := strings.ToLower(in.Name)
		rows := make([]componentOutput, 0, len(all))
		for _, c := range all {
			if in.VulnerableOnly && derefInt(c.VulnCount) == 0 {
				continue
			}
			if in.DirectOnly && !c.IsDirect {
				continue
			}
			if name != "" && !strings.Contains(strings.ToLower(c.Name), name) {
				continue
			}
			rows = append(rows, componentOutput{
				ID:          c.Id,
				Name:        c.Name,
				Version:     deref(c.Version),
				Group:       deref(c.Group),
				Purl:        deref(c.Purl),
				Type:        c.Type,
				SBOMID:      c.SbomId,
				IsDirect:    c.IsDirect,
				VulnCount:   derefInt(c.VulnCount),
				MaxSeverity: deref(c.MaxSeverity),
			})
		}
		if in.VulnerableOnly {
			sort.SliceStable(rows, func(i, j int) bool {
				ri, rj := severityRank(rows[i].MaxSeverity), severityRank(rows[j].MaxSeverity)
				if ri != rj {
					return ri < rj
				}
				return rows[i].VulnCount > rows[j].VulnCount
			})
		}
		limit := pageLimit(in.Limit, defaultSearchLimit)
		return nil, listSBOMComponentsOutput{
			SBOMID:     in.SBOMID,
			Components: pageSlice(rows, int(in.Offset), int(limit)),
			Total:      int64(len(rows)),
			Limit:      limit,
			Offset:     in.Offset,
		}, nil
	})
}

type relationOutput struct {
	ArtifactID     string `json:"artifact_id" jsonschema:"UUID of the related artifact"`
	Name           string `json:"name"`
	Group          string `json:"group,omitempty"`
	Type           string `json:"type"`
	SBOMID         string `json:"sbom_id" jsonschema:"SBOM in which the relation was observed"`
	MatchedVersion string `json:"matched_version,omitempty" jsonschema:"Version of the related artifact that was matched"`
	CurrentVersion string `json:"current_version,omitempty" jsonschema:"Latest catalogued version of the related artifact"`
	IsCurrent      *bool  `json:"is_current,omitempty" jsonschema:"Whether the matched version is the latest; false on a base image means a rebuild picks up newer fixes"`
	Flavor         string `json:"flavor,omitempty"`
}

type artifactLineageInput struct {
	ArtifactID string `json:"artifact_id" jsonschema:"UUID of the artifact, as returned by ocidex_lookup_artifact"`
}

type artifactLineageOutput struct {
	ArtifactID string           `json:"artifact_id"`
	Contains   []relationOutput `json:"contains" jsonschema:"Catalogued artifacts found inside this one's latest SBOM: for an image, its base image"`
	UsedBy     []relationOutput `json:"used_by" jsonschema:"Artifacts whose latest SBOM contains this one: for a base image, the images built on it"`
}

func toRelations(rs []client.ArtifactRelation) []relationOutput {
	out := make([]relationOutput, 0, len(rs))
	for _, r := range rs {
		out = append(out, relationOutput{
			ArtifactID:     r.ArtifactId,
			Name:           r.ArtifactName,
			Group:          deref(r.ArtifactGroup),
			Type:           r.ArtifactType,
			SBOMID:         r.SbomId,
			MatchedVersion: deref(r.MatchedVersion),
			CurrentVersion: deref(r.CurrentVersion),
			IsCurrent:      r.IsCurrent,
			Flavor:         deref(r.Flavor),
		})
	}
	return out
}

func registerLineageTool(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_artifact_lineage",
		Description: "Report which catalogued artifacts this one is built from (contains: usually its base " +
			"image) and which are built on it (used_by). In remediation this decides between bumping " +
			"packages and bumping the base image: if the vulnerable packages come from a base image " +
			"whose is_current is false, rebuilding on its current version may clear them all at once. " +
			"For a base image, used_by is the list of images to rebuild after it is fixed.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in artifactLineageInput) (*mcp.CallToolResult, artifactLineageOutput, error) {
		contains, err := api.GetArtifactContains(ctx, in.ArtifactID)
		if err != nil {
			return nil, artifactLineageOutput{}, toolError(fmt.Sprintf("finding what artifact %s contains", in.ArtifactID), err)
		}
		usages, err := api.GetArtifactUsages(ctx, in.ArtifactID)
		if err != nil {
			return nil, artifactLineageOutput{}, toolError(fmt.Sprintf("finding what uses artifact %s", in.ArtifactID), err)
		}
		return nil, artifactLineageOutput{
			ArtifactID: in.ArtifactID,
			Contains:   toRelations(contains),
			UsedBy:     toRelations(usages),
		}, nil
	})
}

type componentVersionsInput struct {
	Name    string `json:"name" jsonschema:"Component name, e.g. openssl"`
	Group   string `json:"group,omitempty" jsonschema:"Component group, where the ecosystem has one"`
	Type    string `json:"type,omitempty" jsonschema:"CycloneDX component type, e.g. library"`
	Version string `json:"version,omitempty" jsonschema:"Only this component version"`
}

type componentVersionOutput struct {
	ComponentID  string `json:"component_id" jsonschema:"Occurrence id; pass it to ocidex_component_vulnerabilities"`
	Version      string `json:"version,omitempty" jsonschema:"Component version"`
	Purl         string `json:"purl,omitempty"`
	ArtifactID   string `json:"artifact_id,omitempty" jsonschema:"Artifact shipping this occurrence"`
	ArtifactName string `json:"artifact_name,omitempty"`
	SubjectVer   string `json:"artifact_version,omitempty" jsonschema:"Version of that artifact"`
	Architecture string `json:"architecture,omitempty"`
	SBOMID       string `json:"sbom_id"`
	VulnCount    int64  `json:"vuln_count" jsonschema:"Known vulnerabilities on this occurrence; 0 marks a version that is already clean somewhere in the catalog"`
	MaxSeverity  string `json:"max_severity,omitempty"`
}

type componentVersionsOutput struct {
	Name          string                   `json:"name"`
	Occurrences   []componentVersionOutput `json:"occurrences" jsonschema:"Where each version of the component ships"`
	VersionCount  int64                    `json:"version_count" jsonschema:"Distinct versions across the catalog"`
	ArtifactCount int64                    `json:"artifact_count" jsonschema:"Distinct artifacts shipping the component"`
	Total         int64                    `json:"total" jsonschema:"Occurrences across all pages"`
}

func registerComponentVersionsTool(srv *mcp.Server, api client.Client) {
	addTool(srv, &mcp.Tool{
		Name: "ocidex_component_versions",
		Description: "Show every version of one component across the catalog and which artifacts ship each, " +
			"with vulnerability counts. Use it to check that a fixed version is already in production " +
			"elsewhere (evidence the upgrade is safe), or to find the other images that still ship the " +
			"vulnerable version and need the same fix.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in componentVersionsInput) (*mcp.CallToolResult, componentVersionsOutput, error) {
		if in.Name == "" {
			return nil, componentVersionsOutput{}, errors.New("component versions needs a name")
		}
		res, err := api.GetComponentVersions(ctx, client.GetComponentVersionsParams{
			Name:    in.Name,
			Group:   optional(in.Group),
			Type:    optional(in.Type),
			Version: optional(in.Version),
		})
		if err != nil {
			return nil, componentVersionsOutput{}, toolError(fmt.Sprintf("listing versions of component %q", in.Name), err)
		}
		out := componentVersionsOutput{
			Name:          in.Name,
			Occurrences:   make([]componentVersionOutput, 0, len(derefSlice(res.Versions))),
			VersionCount:  res.VersionCount,
			ArtifactCount: res.ArtifactCount,
			Total:         res.Pagination.Total,
		}
		for _, v := range derefSlice(res.Versions) {
			out.Occurrences = append(out.Occurrences, componentVersionOutput{
				ComponentID:  v.Id,
				Version:      deref(v.Version),
				Purl:         deref(v.Purl),
				ArtifactID:   deref(v.ArtifactId),
				ArtifactName: deref(v.ArtifactName),
				SubjectVer:   deref(v.SubjectVersion),
				Architecture: deref(v.Architecture),
				SBOMID:       v.SbomId,
				VulnCount:    v.VulnCount,
				MaxSeverity:  deref(v.MaxSeverity),
			})
		}
		return nil, out, nil
	})
}
