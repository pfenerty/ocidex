package main

import (
	"context"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

func TestArtifactResourceTemplate(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{GetArtifactFn: func(_ context.Context, id string) (client.ArtifactDetail, error) {
		i.Equal(id, "a-1")
		return client.ArtifactDetail{Id: "a-1", Name: "ghcr.io/acme/api\u202e"}, nil
	}}
	session := connect(t, api)
	tmpls, err := session.ListResourceTemplates(t.Context(), nil)
	i.NoErr(err)
	uris := map[string]bool{}
	for _, tm := range tmpls.ResourceTemplates {
		uris[tm.URITemplate] = true
	}
	i.True(uris[artifactTemplate] && uris[sbomTemplate])

	res, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "ocidex://artifact/a-1"})
	i.NoErr(err)
	text := res.Contents[0].Text
	i.True(strings.Contains(text, `"ghcr.io/acme/api"`)) // sanitized like tool output
}

func TestSBOMResourceTemplateNotFound(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{GetSBOMFn: func(context.Context, string, bool) (client.SBOMDetail, error) {
		return client.SBOMDetail{}, client.ErrNotFound
	}}
	_, err := connect(t, api).ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "ocidex://sbom/missing"})
	i.True(err != nil)
}

func complete(t *testing.T, session *mcp.ClientSession, prompt, arg, value string) []string {
	t.Helper()
	res, err := session.Complete(t.Context(), &mcp.CompleteParams{
		Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: prompt},
		Argument: mcp.CompleteParamsArgument{Name: arg, Value: value},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	return res.Completion.Values
}

func TestCompletionOffersNames(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		ListArtifactsFn: func(_ context.Context, f client.ArtifactFilter, _ client.PageOpts) (client.CursorPage[client.ArtifactSummary], error) {
			i.Equal(f.Name, "acme")
			return client.CursorPage[client.ArtifactSummary]{Data: []client.ArtifactSummary{{Name: "ghcr.io/acme/web"}, {Name: "ghcr.io/acme/api"}}}, nil
		},
		ListClustersFn: func(context.Context, string) ([]client.ClusterResponse, error) {
			return []client.ClusterResponse{{Name: "homelab"}, {Name: "dev-cluster"}, {Name: "prod"}}, nil
		},
	}
	session := connect(t, api)
	i.Equal(complete(t, session, "remediate_image", "image", "acme"), []string{"ghcr.io/acme/api", "ghcr.io/acme/web"})
	i.Equal(complete(t, session, "remediate_cluster", "cluster", "LAB"), []string{"homelab"})
	i.Equal(len(complete(t, session, "remediate_cluster", "k8s_namespace", "x")), 0)
}

func TestCompletionCapsTheList(t *testing.T) {
	i := is.New(t)
	names := make([]string, 30)
	for n := range names {
		names[n] = "ns-" + string(rune('a'+n%26)) + string(rune('a'+n/26))
	}
	res := completion(names)
	i.Equal(len(res.Completion.Values), maxCompletions)
	i.True(res.Completion.HasMore)
	i.Equal(res.Completion.Total, 30)
}

// Every tool declares its output, so a client can validate results and a
// model can plan with them.
func TestEveryToolHasAnOutputSchema(t *testing.T) {
	session := connect(t, &client.FakeClient{GetKeySelfFn: agentSelf([]string{"read_private", "trigger_scan", "ingest"}, nil)})
	for name, tool := range listedTools(t, session) {
		if tool.OutputSchema == nil {
			t.Errorf("%s has no output schema", name)
		}
	}
}

// Paging is uniform: a tool that takes an offset says where the next page
// starts, and one that takes a cursor returns the next cursor.
func TestPagingIsUniform(t *testing.T) {
	session := connect(t, &client.FakeClient{GetKeySelfFn: agentSelf([]string{"read_private", "trigger_scan", "ingest"}, nil)})
	paged := 0
	for name, tool := range listedTools(t, session) {
		in, out := topProps(tool.InputSchema), topProps(tool.OutputSchema)
		if in["offset"] {
			paged++
		}
		if in["offset"] && !out["next_offset"] {
			t.Errorf("%s takes offset but returns no next_offset", name)
		}
		if in["cursor"] && !out["next_cursor"] {
			t.Errorf("%s takes cursor but returns no next_cursor", name)
		}
	}
	if paged < 10 { // guards against the schemas not decoding as expected
		t.Fatalf("only %d tools take an offset", paged)
	}
}

func TestNextOffset(t *testing.T) {
	i := is.New(t)
	i.Equal(nextOffset(0, 50, 120), int32(50))
	i.Equal(nextOffset(100, 50, 120), int32(0))
	i.Equal(nextOffset(0, 0, 10), int32(0))
	out := struct {
		Total      int64
		Limit      int32
		Offset     int32
		NextOffset int32
	}{Total: 30, Limit: 10, Offset: 10}
	fillNextOffset(&out)
	i.Equal(out.NextOffset, int32(20))
}

// topProps is a schema's top-level property names.
func topProps(schema any) map[string]bool {
	out := map[string]bool{}
	if m, ok := schema.(map[string]any); ok {
		if props, ok := m["properties"].(map[string]any); ok {
			for k := range props {
				out[k] = true
			}
		}
	}
	return out
}
