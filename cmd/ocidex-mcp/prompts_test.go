package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// toolNamePattern finds tool references in prose the model reads: the server
// instructions and the prompt bodies.
var toolNamePattern = regexp.MustCompile(`\bocidex_[a-z_]+\b`)

func listedTools(t *testing.T, session *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	res, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("listing tools: %v", err)
	}
	out := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		out[tool.Name] = tool
	}
	return out
}

// Guidance that names a tool which does not exist sends the model into an
// error it cannot recover from, so every reference is checked. The workflow
// lines in the instructions drop the ocidex_ prefix for brevity; those are
// checked by their bare names.
func TestGuidanceNamesOnlyRealTools(t *testing.T) {
	i := is.New(t)
	session := connect(t, &client.FakeClient{})
	tools := listedTools(t, session)

	texts := []string{session.InitializeResult().Instructions}
	for _, p := range []struct{ name, argKey, argVal string }{
		{"remediate_image", "image", "ghcr.io/acme/api"},
		{"remediate_cluster", "cluster", "homelab"},
	} {
		res, err := session.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: p.name, Arguments: map[string]string{p.argKey: p.argVal}})
		i.NoErr(err)
		text := res.Messages[0].Content.(*mcp.TextContent).Text
		i.True(strings.Contains(text, p.argVal))
		texts = append(texts, text)
	}

	for _, text := range texts {
		for _, name := range toolNamePattern.FindAllString(text, -1) {
			if _, ok := tools[name]; !ok {
				t.Errorf("guidance names unknown tool %s", name)
			}
		}
	}

	bare := regexp.MustCompile(`(?:^|[\s>(])([a-z]+(?:_[a-z]+)+)(?:\s|$|[(,])`)
	for _, line := range strings.Split(session.InitializeResult().Instructions, "\n") {
		if !strings.Contains(line, "->") && !strings.Contains(line, "Where to start") {
			continue
		}
		for _, m := range bare.FindAllStringSubmatch(line, -1) {
			word := m[1]
			if strings.Contains(word, "group_by") || strings.HasPrefix(word, "sbom_id") || word == "sort" {
				continue
			}
			if _, ok := tools["ocidex_"+word]; !ok && !strings.Contains(word, "=") {
				t.Errorf("instructions workflow names unknown tool %s", word)
			}
		}
	}
}

func TestPromptsRequireTheirSubject(t *testing.T) {
	i := is.New(t)
	session := connect(t, &client.FakeClient{})
	_, err := session.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "remediate_cluster", Arguments: map[string]string{}})
	i.True(err != nil)
}

func TestRemediateClusterScopesToNamespace(t *testing.T) {
	i := is.New(t)
	session := connect(t, &client.FakeClient{})
	res, err := session.GetPrompt(t.Context(), &mcp.GetPromptParams{
		Name: "remediate_cluster", Arguments: map[string]string{"cluster": "homelab", "k8s_namespace": "prod"},
	})
	i.NoErr(err)
	i.True(strings.Contains(res.Messages[0].Content.(*mcp.TextContent).Text, `"prod"`))
}

// idProducers names, for every id-shaped tool argument, a tool whose output
// hands that id out. An argument no tool produces is unreachable: the model
// can only fill it by guessing, which is how ocidex_component_vulnerabilities
// once shipped unusable. The test fails both when a producer stops emitting the
// field and when a new id argument appears without an entry here.
var idProducers = map[string]struct{ tool, field string }{
	"artifact_id":  {"ocidex_lookup_artifact", "id"},
	"sbom_id":      {"ocidex_list_artifact_versions", "sbom_id"},
	"from_sbom_id": {"ocidex_artifact_changelog", "from"},
	"to_sbom_id":   {"ocidex_artifact_changelog", "to"},
	"component_id": {"ocidex_list_sbom_components", "id"},
	"vuln_id":      {"ocidex_sbom_findings", "id"},
	"cluster":      {"ocidex_list_clusters", "name"},
	"node":         {"ocidex_diff_sboms", "node_ref"},
	"id":           {"ocidex_lookup_artifact", "id"},
}

// schemaProps collects every property name anywhere in a JSON schema.
func schemaProps(v any, into map[string]bool) {
	switch s := v.(type) {
	case map[string]any:
		if props, ok := s["properties"].(map[string]any); ok {
			for k, sub := range props {
				into[k] = true
				schemaProps(sub, into)
			}
		}
		for k, sub := range s {
			if k != "properties" {
				schemaProps(sub, into)
			}
		}
	case []any:
		for _, sub := range s {
			schemaProps(sub, into)
		}
	}
}

func schemaOf(t *testing.T, schema any) map[string]bool {
	t.Helper()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	props := map[string]bool{}
	schemaProps(v, props)
	return props
}

func isIDArgument(name string) bool {
	return name == "id" || name == "node" || name == "cluster" || strings.HasSuffix(name, "_id")
}

func TestEveryIDArgumentHasAProducer(t *testing.T) {
	tools := listedTools(t, connect(t, &client.FakeClient{}))

	// Natural keys the user supplies, not ids a tool must hand out.
	userSupplied := map[string]bool{"spdx_id": true}

	for name, tool := range tools {
		for arg := range schemaOf(t, tool.InputSchema) {
			if !isIDArgument(arg) || userSupplied[arg] {
				continue
			}
			p, ok := idProducers[arg]
			if !ok {
				t.Errorf("%s takes %s, but no producer is recorded for it", name, arg)
				continue
			}
			producer, ok := tools[p.tool]
			if !ok {
				t.Errorf("%s: producer %s for %s does not exist", name, p.tool, arg)
				continue
			}
			if !schemaOf(t, producer.OutputSchema)[p.field] {
				t.Errorf("%s: producer %s no longer outputs %s for %s", name, p.tool, p.field, arg)
			}
		}
	}
}
