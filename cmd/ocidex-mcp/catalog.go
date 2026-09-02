package main

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// defaultSearchLimit keeps an unbounded search from filling a model's context
// with rows it will not read. It matches the server's own default so that
// omitting the argument and passing the default behave identically.
const defaultSearchLimit = 50

// qualifierLadder phrases ADR-042's narrowing rule once, for the tool
// descriptions that share it. An agent that reads only the description of the
// tool it picked still learns how to resolve the ambiguity it is about to hit.
const qualifierLadder = "Ambiguity is resolved by adding qualifiers in order, not by guessing: " +
	"if the call reports several candidates, retry with the next qualifier taken from the " +
	"candidate list it returned."

// registerCatalogTools adds the read tools built on the ADR-042 name-keyed
// resolvers, plus the UUID and listing calls an agent needs to move between
// them.
//
// The name-keyed tools come first deliberately: an agent starts from an image
// name it read in a manifest or a log, never from a UUID, and every id it can
// use later comes out of one of these lookups.
func registerCatalogTools(srv *mcp.Server, api client.Client) {
	registerArtifactTools(srv, api)
	registerSBOMTools(srv, api)
	registerLicenseTools(srv, api)
	registerComponentTools(srv, api)
	registerNamespaceTools(srv, api)
}

// optional converts an empty-string argument into the absent pointer
// pkg/client expects. Optional arguments are plain strings rather than
// pointers so the generated tool schema stays free of null-vs-absent
// distinctions that mean nothing to a model.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// optionalInt32 is optional's counterpart for a bounded numeric argument, where
// the tool schema carries a plain int and the generated client wants a pointer.
//
// Every caller is a page size a model asked for, so the clamp is not
// defensive noise: an int argument can hold more than an int32, and the API's
// own maximum is two orders of magnitude below either.
func optionalInt32(v int) *int32 {
	if v > math.MaxInt32 {
		v = math.MaxInt32
	}
	if v < 0 {
		v = 0
	}
	n := int32(v)
	return &n
}

// deref renders an optional API field for output structs, where "" and absent
// are the same thing to a reader.
func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// derefSlice flattens the *[]T that the generated types use for JSON arrays.
// A nil pointer and an empty array mean the same thing to a reader, and the
// distinction only invites nil checks at every call site.
func derefSlice[T any](v *[]T) []T {
	if v == nil {
		return nil
	}
	return *v
}

func derefInt(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// artifactOutput is the shape every artifact-returning tool answers with, so a
// model learns one set of field names. It is a projection of
// client.ArtifactDetail rather than the type itself: the generated struct
// carries $schema and other transport detail that would only add noise to the
// tool's output schema.
type artifactOutput struct {
	ID                  string `json:"id" jsonschema:"UUID of the artifact; pass this to tools that take an artifact id"`
	Name                string `json:"name" jsonschema:"Artifact name, e.g. ghcr.io/pfenerty/ocidex"`
	Type                string `json:"type" jsonschema:"CycloneDX component type, e.g. container or application"`
	Group               string `json:"group,omitempty" jsonschema:"Artifact group, where the ecosystem has one"`
	Purl                string `json:"purl,omitempty" jsonschema:"Package URL of the artifact"`
	SBOMCount           int64  `json:"sbom_count" jsonschema:"Number of SBOMs recorded for this artifact"`
	SufficientSBOMCount int64  `json:"sufficient_sbom_count" jsonschema:"SBOMs complete enough to be trusted for diff and vulnerability answers"`
	VersionCount        int64  `json:"version_count" jsonschema:"Number of distinct versions recorded"`
	SigningStatus       string `json:"signing_status" jsonschema:"Provenance verification status across this artifact's SBOMs"`
}

func toArtifactOutput(a client.ArtifactDetail) artifactOutput {
	return artifactOutput{
		ID:                  a.Id,
		Name:                a.Name,
		Type:                a.Type,
		Group:               deref(a.Group),
		Purl:                deref(a.Purl),
		SBOMCount:           a.SbomCount,
		SufficientSBOMCount: a.SufficientSbomCount,
		VersionCount:        a.VersionCount,
		SigningStatus:       a.SigningStatus,
	}
}

type lookupArtifactInput struct {
	Name  string `json:"name" jsonschema:"Exact artifact name, e.g. ghcr.io/pfenerty/ocidex"`
	Type  string `json:"type,omitempty" jsonschema:"First narrowing qualifier: CycloneDX type, e.g. container or application"`
	Group string `json:"group,omitempty" jsonschema:"Second narrowing qualifier: artifact group"`
}

type getArtifactInput struct {
	ID string `json:"id" jsonschema:"UUID of the artifact, as returned by ocidex_lookup_artifact"`
}

func registerArtifactTools(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_lookup_artifact",
		Description: "Find one artifact by its exact name and return its id, counts and signing status. " +
			"This is the usual entry point: start from the name you have, and use the id it returns " +
			"for tools that take an artifact id. The qualifier ladder is name, then type, then group. " +
			qualifierLadder,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in lookupArtifactInput) (*mcp.CallToolResult, artifactOutput, error) {
		artifact, err := api.LookupArtifact(ctx, client.LookupArtifactParams{
			Name:  in.Name,
			Type:  optional(in.Type),
			Group: optional(in.Group),
		})
		if err != nil {
			return nil, artifactOutput{}, toolError(fmt.Sprintf("looking up artifact %q", in.Name), err)
		}
		return nil, toArtifactOutput(artifact), nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_get_artifact",
		Description: "Fetch an artifact by its UUID. Use this only when you already hold an id — " +
			"if you have a name, call ocidex_lookup_artifact instead.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in getArtifactInput) (*mcp.CallToolResult, artifactOutput, error) {
		artifact, err := api.GetArtifact(ctx, in.ID)
		if err != nil {
			return nil, artifactOutput{}, toolError(fmt.Sprintf("fetching artifact %s", in.ID), err)
		}
		return nil, toArtifactOutput(artifact), nil
	})
}

// sbomOutput reports the identity axes an SBOM is looked up by — version,
// architecture, flavor, digest — alongside its id, so that a result which came
// back from an under-qualified query still shows which one of the candidates
// was chosen.
type sbomOutput struct {
	ID             string `json:"id" jsonschema:"UUID of the SBOM"`
	ArtifactID     string `json:"artifact_id,omitempty" jsonschema:"UUID of the artifact this SBOM describes"`
	Version        string `json:"version,omitempty" jsonschema:"Artifact version this SBOM describes"`
	Architecture   string `json:"architecture,omitempty" jsonschema:"Architecture qualifier, e.g. amd64"`
	Flavor         string `json:"flavor,omitempty" jsonschema:"Image flavor qualifier (ADR-020), e.g. alpine or distroless"`
	Digest         string `json:"digest,omitempty" jsonschema:"Digest of the described artifact; unique across the catalog"`
	ComponentCount int64  `json:"component_count" jsonschema:"Number of components recorded in this SBOM"`
	PackageCount   int64  `json:"package_count" jsonschema:"Number of packages recorded in this SBOM"`
	SpecVersion    string `json:"spec_version" jsonschema:"CycloneDX specification version of the source document"`
	SigningStatus  string `json:"signing_status" jsonschema:"Provenance verification status of this SBOM"`
	Sufficient     bool   `json:"sufficient" jsonschema:"Whether the SBOM is complete enough to be trusted for diff and vulnerability answers"`
}

func toSBOMOutput(s client.SBOMDetail) sbomOutput {
	return sbomOutput{
		ID:             s.Id,
		ArtifactID:     deref(s.ArtifactId),
		Version:        deref(s.ImageVersion),
		Architecture:   deref(s.Architecture),
		Flavor:         deref(s.Flavor),
		Digest:         deref(s.Digest),
		ComponentCount: derefInt(s.ComponentCount),
		PackageCount:   s.PackageCount,
		SpecVersion:    s.SpecVersion,
		SigningStatus:  s.SigningStatus,
		Sufficient:     s.Sufficient,
	}
}

type lookupSBOMInput struct {
	Artifact string `json:"artifact,omitempty" jsonschema:"Exact artifact name; required unless digest is given"`
	Version  string `json:"version,omitempty" jsonschema:"Artifact version, e.g. 1.2.3; required unless digest is given"`
	Arch     string `json:"arch,omitempty" jsonschema:"First narrowing qualifier: architecture, e.g. amd64"`
	Flavor   string `json:"flavor,omitempty" jsonschema:"Second narrowing qualifier: image flavor (ADR-020), e.g. alpine"`
	Digest   string `json:"digest,omitempty" jsonschema:"Digest of the described artifact; unique, so it never needs qualifiers"`
}

func registerSBOMTools(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_lookup_sbom",
		Description: "Find one SBOM, either by digest or by artifact name plus version. " +
			"A digest identifies an SBOM outright and never needs narrowing. By name the qualifier " +
			"ladder is artifact and version, then arch, then flavor — a multi-architecture or " +
			"multi-flavor release has one SBOM per combination, so name and version alone are often " +
			"ambiguous. " + qualifierLadder,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in lookupSBOMInput) (*mcp.CallToolResult, sbomOutput, error) {
		// Checked here rather than left to the server: the schema cannot express
		// "digest, or else artifact and version", and a 400 round trip would tell
		// the model less than this does.
		if in.Digest == "" && (in.Artifact == "" || in.Version == "") {
			return nil, sbomOutput{}, errors.New(
				"looking up an SBOM needs either digest, or both artifact and version; " +
					"call ocidex_lookup_artifact first if you only have a name")
		}
		sbom, err := api.LookupSBOM(ctx, client.LookupSbomParams{
			Artifact: optional(in.Artifact),
			Version:  optional(in.Version),
			Arch:     optional(in.Arch),
			Flavor:   optional(in.Flavor),
			Digest:   optional(in.Digest),
		})
		if err != nil {
			return nil, sbomOutput{}, toolError(describeSBOMQuery(in), err)
		}
		return nil, toSBOMOutput(sbom), nil
	})
}

// describeSBOMQuery echoes back what was actually asked for, so a candidate
// list arrives attached to the query that produced it rather than to a generic
// "looking up SBOM".
func describeSBOMQuery(in lookupSBOMInput) string {
	if in.Digest != "" {
		return fmt.Sprintf("looking up SBOM with digest %s", in.Digest)
	}
	return fmt.Sprintf("looking up SBOM for %s version %s", in.Artifact, in.Version)
}

type licenseOutput struct {
	ID             string `json:"id" jsonschema:"UUID of the license record"`
	SpdxID         string `json:"spdx_id,omitempty" jsonschema:"SPDX identifier, e.g. Apache-2.0"`
	Name           string `json:"name" jsonschema:"Human-readable license name"`
	Category       string `json:"category" jsonschema:"License category, e.g. permissive or copyleft"`
	ComponentCount int64  `json:"component_count" jsonschema:"Number of visible components carrying this license"`
	URL            string `json:"url,omitempty" jsonschema:"Canonical URL of the license text"`
}

type lookupLicenseInput struct {
	SpdxID string `json:"spdx_id" jsonschema:"SPDX identifier, e.g. Apache-2.0 or GPL-3.0-only"`
}

func registerLicenseTools(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_lookup_license",
		Description: "Find a license by SPDX identifier and report how many visible components carry it. " +
			"The SPDX id is a natural key, so this lookup is never ambiguous and takes no qualifiers: " +
			"it either matches or it does not.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in lookupLicenseInput) (*mcp.CallToolResult, licenseOutput, error) {
		license, err := api.LookupLicense(ctx, in.SpdxID)
		if err != nil {
			return nil, licenseOutput{}, toolError(fmt.Sprintf("looking up license %s", in.SpdxID), err)
		}
		return nil, licenseOutput{
			ID:             license.Id,
			SpdxID:         deref(license.SpdxId),
			Name:           license.Name,
			Category:       license.Category,
			ComponentCount: license.ComponentCount,
			URL:            deref(license.Url),
		}, nil
	})
}

type componentOutput struct {
	// The id is what ocidex_component_vulnerabilities takes, and this is the only
	// tool that hands one out — omitting it left that tool unreachable.
	ID          string `json:"id" jsonschema:"UUID of this component occurrence; pass it to ocidex_component_vulnerabilities"`
	Name        string `json:"name" jsonschema:"Component name"`
	Version     string `json:"version,omitempty" jsonschema:"Component version as recorded in the SBOM"`
	Group       string `json:"group,omitempty" jsonschema:"Component group, where the ecosystem has one"`
	Purl        string `json:"purl,omitempty" jsonschema:"Package URL; the cross-SBOM key for this component"`
	Type        string `json:"type" jsonschema:"CycloneDX component type, e.g. library"`
	SBOMID      string `json:"sbom_id" jsonschema:"UUID of the SBOM this occurrence was found in"`
	IsDirect    bool   `json:"is_direct" jsonschema:"Whether the component is a direct dependency of the artifact"`
	VulnCount   int64  `json:"vuln_count,omitempty" jsonschema:"Known vulnerabilities affecting this occurrence"`
	MaxSeverity string `json:"max_severity,omitempty" jsonschema:"Highest severity among those vulnerabilities"`
}

// searchComponentsOutput reports the page it returned alongside the total, so a
// model can tell "these are all of them" from "these are the first 50" without
// a second call.
type searchComponentsOutput struct {
	Components []componentOutput `json:"components" jsonschema:"Matching occurrences, one row per SBOM the component appears in"`
	Total      int64             `json:"total" jsonschema:"Total matching occurrences across all pages"`
	Limit      int32             `json:"limit" jsonschema:"Page size that was applied"`
	Offset     int32             `json:"offset" jsonschema:"Offset that was applied"`
}

type searchComponentsInput struct {
	Name    string `json:"name,omitempty" jsonschema:"Component name to match; supply this or purl"`
	Purl    string `json:"purl,omitempty" jsonschema:"Exact package URL to match; supply this or name"`
	Group   string `json:"group,omitempty" jsonschema:"Narrow by component group"`
	Version string `json:"version,omitempty" jsonschema:"Narrow to a single component version"`
	Limit   int32  `json:"limit,omitempty" jsonschema:"Maximum rows to return; defaults to 50"`
	Offset  int32  `json:"offset,omitempty" jsonschema:"Rows to skip, for paging through a large result"`
}

func registerComponentTools(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_search_components",
		Description: "Find where a component appears across the catalog, one row per SBOM it is in. " +
			"Supply name or purl — purl matches exactly and is the reliable key across SBOMs, while " +
			"name matches more loosely and is the right choice when you only know what something is " +
			"called. Narrow further with group and version. Use this to answer \"which images ship " +
			"this package\".",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in searchComponentsInput) (*mcp.CallToolResult, searchComponentsOutput, error) {
		// The server requires one of the two; saying so here costs no round trip
		// and names both options, which a 400 would not.
		if in.Name == "" && in.Purl == "" {
			return nil, searchComponentsOutput{}, errors.New(
				"searching components needs either name or purl; " +
					"use purl for an exact match, name when you only know what the package is called")
		}
		limit := in.Limit
		if limit <= 0 {
			limit = defaultSearchLimit
		}
		page, err := api.SearchComponents(ctx, client.ComponentFilter{
			Name:    in.Name,
			Purl:    in.Purl,
			Group:   in.Group,
			Version: in.Version,
		}, client.PageOpts{Limit: limit, Offset: in.Offset})
		if err != nil {
			return nil, searchComponentsOutput{}, toolError("searching components", err)
		}

		out := searchComponentsOutput{
			// Non-nil so an empty result serialises as [] rather than null: null
			// reads as "unknown", and here the answer is "nothing visible matched".
			Components: make([]componentOutput, 0, len(page.Data)),
			Total:      page.Pagination.Total,
			Limit:      page.Pagination.Limit,
			Offset:     page.Pagination.Offset,
		}
		for _, c := range page.Data {
			out.Components = append(out.Components, componentOutput{
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
		return nil, out, nil
	})
}

type namespaceOutput struct {
	ID            string `json:"id" jsonschema:"UUID of the namespace"`
	Name          string `json:"name" jsonschema:"Namespace name"`
	Visibility    string `json:"visibility" jsonschema:"public or private"`
	OwnerUsername string `json:"owner_username,omitempty" jsonschema:"GitHub username of the namespace owner"`
}

type listNamespacesOutput struct {
	Namespaces []namespaceOutput `json:"namespaces" jsonschema:"Namespaces this API key can see"`
}

type listNamespacesInput struct{}

func registerNamespaceTools(srv *mcp.Server, api client.Client) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_list_namespaces",
		Description: "List the namespaces the configured API key can see. Every other tool is filtered " +
			"to these, so this is how to tell an empty result caused by visibility from one caused by " +
			"an artifact that genuinely is not catalogued.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listNamespacesInput) (*mcp.CallToolResult, listNamespacesOutput, error) {
		namespaces, err := api.ListNamespaces(ctx)
		if err != nil {
			return nil, listNamespacesOutput{}, toolError("listing namespaces", err)
		}
		out := listNamespacesOutput{Namespaces: make([]namespaceOutput, 0, len(namespaces))}
		for _, ns := range namespaces {
			out.Namespaces = append(out.Namespaces, namespaceOutput{
				ID:            ns.Id,
				Name:          ns.Name,
				Visibility:    string(ns.Visibility),
				OwnerUsername: deref(ns.OwnerUsername),
			})
		}
		return nil, out, nil
	})
}
