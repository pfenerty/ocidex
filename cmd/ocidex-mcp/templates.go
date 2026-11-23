package main

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// Resource templates: an artifact or SBOM addressed by id, for clients that
// attach resources to a conversation rather than calling tools. The content
// is the API's own JSON, sanitized like every tool result.
const (
	mimeJSON = "application/json"

	artifactTemplate = "ocidex://artifact/{id}"
	sbomTemplate     = "ocidex://sbom/{id}"
)

func registerResourceTemplates(srv *mcp.Server, api client.Client) {
	srv.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: artifactTemplate,
		Name:        "artifact",
		Title:       "OCIDex artifact",
		MIMEType:    mimeJSON,
		Description: "An artifact by UUID: its name, type and latest version, as JSON.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		id, ok := strings.CutPrefix(req.Params.URI, "ocidex://artifact/")
		if !ok || id == "" {
			return nil, mcp.ResourceNotFoundError(req.Params.URI)
		}
		a, err := api.GetArtifact(ctx, id)
		if err != nil {
			return nil, toolError("fetching artifact "+id, err)
		}
		return jsonResource(req.Params.URI, &a)
	})
	srv.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: sbomTemplate,
		Name:        "sbom",
		Title:       "OCIDex SBOM",
		MIMEType:    mimeJSON,
		Description: "An SBOM by UUID: its artifact, version, digest and enrichment, as JSON (not the raw document).",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		id, ok := strings.CutPrefix(req.Params.URI, "ocidex://sbom/")
		if !ok || id == "" {
			return nil, mcp.ResourceNotFoundError(req.Params.URI)
		}
		s, err := api.GetSBOM(ctx, id, false)
		if err != nil {
			return nil, toolError("fetching SBOM "+id, err)
		}
		return jsonResource(req.Params.URI, &s)
	})
}

// jsonResource renders v, a pointer, as sanitized JSON content.
func jsonResource[T any](uri string, v *T) (*mcp.ReadResourceResult, error) {
	sanitizeValue(v)
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: mimeJSON, Text: string(b)}}}, nil
}

// maxCompletions keeps a completion list short enough to read.
const maxCompletions = 20

// completer offers names for arguments that take an artifact, a cluster or a
// namespace, wherever they appear: prompt arguments today, and any later
// argument with one of those names.
func completer(api client.Client) func(context.Context, *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
	return func(ctx context.Context, req *mcp.CompleteRequest) (*mcp.CompleteResult, error) {
		arg := req.Params.Argument
		var names []string
		var err error
		switch arg.Name {
		case "image", "artifact":
			names, err = artifactNames(ctx, api, arg.Value)
		case "cluster":
			names, err = clusterNames(ctx, api, arg.Value)
		case "namespace":
			names, err = namespaceNames(ctx, api, arg.Value)
		}
		if err != nil {
			// A completion is a convenience; failing it would only break typing.
			names = nil
		}
		return completion(names), nil
	}
}

func completion(names []string) *mcp.CompleteResult {
	sort.Strings(names)
	res := &mcp.CompleteResult{Completion: mcp.CompletionResultDetails{Values: []string{}, Total: len(names)}}
	if len(names) > maxCompletions {
		names, res.Completion.HasMore = names[:maxCompletions], true
	}
	for _, n := range names {
		res.Completion.Values = append(res.Completion.Values, sanitizeString(n))
	}
	return res
}

func artifactNames(ctx context.Context, api client.Client, typed string) ([]string, error) {
	page, err := api.ListArtifacts(ctx, client.ArtifactFilter{Name: typed}, client.PageOpts{Limit: maxCompletions + 1})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(page.Data))
	for _, a := range page.Data {
		out = append(out, a.Name)
	}
	return out, nil
}

func clusterNames(ctx context.Context, api client.Client, typed string) ([]string, error) {
	cs, err := api.ListClusters(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range cs {
		if matches(c.Name, typed) {
			out = append(out, c.Name)
		}
	}
	return out, nil
}

func namespaceNames(ctx context.Context, api client.Client, typed string) ([]string, error) {
	ns, err := api.ListNamespaces(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range ns {
		if matches(n.Name, typed) {
			out = append(out, n.Name)
		}
	}
	return out, nil
}

func matches(name, typed string) bool {
	return strings.Contains(strings.ToLower(name), strings.ToLower(typed))
}
