package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

func sliceptr[T any](v []T) *[]T { return &v }

func float32ptr(v float32) *float32 { return &v }

func diffFixture() client.ChangelogEntry {
	return client.ChangelogEntry{
		From:    client.SBOMRef{Id: "s1", SubjectVersion: strptr("1.0.0"), Architecture: strptr("amd64")},
		To:      client.SBOMRef{Id: "s2", SubjectVersion: strptr("1.1.0"), Architecture: strptr("amd64")},
		Summary: client.ChangeSummary{Added: 1, Removed: 1, Upgraded: 1},
		Changes: sliceptr([]client.ComponentDiff{
			{Direction: "added", Name: "zlib", Type: "library", Version: strptr("1.3")},
			{Direction: "removed", Name: "bzip2", Type: "library", PreviousVersion: strptr("1.0.8")},
			{
				Direction:       "upgraded",
				Name:            "openssl",
				Type:            "library",
				PreviousVersion: strptr("3.0.1"),
				Version:         strptr("3.0.2"),
				NodeRef:         strptr("node-openssl"),
			},
		}),
	}
}

func TestDiffSBOMsSummarisesAndPages(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		DiffSBOMsFn: func(_ context.Context, fromID, toID string) (client.ChangelogEntry, error) {
			i.Equal(fromID, "s1")
			i.Equal(toID, "s2")
			return diffFixture(), nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_diff_sboms", map[string]any{
		"from_sbom_id": "s1",
		"to_sbom_id":   "s2",
	})
	i.True(!res.IsError)

	text := resultText(res)
	// The summary describes the whole diff, and the node_ref is what makes a
	// change walkable in the tree tool.
	i.True(strings.Contains(text, `"upgraded":1`))
	i.True(strings.Contains(text, "node-openssl"))
	i.True(strings.Contains(text, `"total":3`))
	i.True(strings.Contains(text, `"truncated":false`))
}

func TestDiffSBOMsFiltersByDirection(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		DiffSBOMsFn: func(context.Context, string, string) (client.ChangelogEntry, error) {
			return diffFixture(), nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_diff_sboms", map[string]any{
		"from_sbom_id": "s1",
		"to_sbom_id":   "s2",
		"direction":    "upgraded",
	})
	i.True(!res.IsError)

	text := resultText(res)
	i.True(strings.Contains(text, "openssl"))
	i.True(!strings.Contains(text, "bzip2"))
	// The filtered total is the count of matching changes, while the summary
	// still reports every direction.
	i.True(strings.Contains(text, `"total":1`))
	i.True(strings.Contains(text, `"removed":1`))
}

// A window past the end must be an empty page, not a panic or a wrapped slice.
func TestDiffSBOMsPagesBeyondEnd(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		DiffSBOMsFn: func(context.Context, string, string) (client.ChangelogEntry, error) {
			return diffFixture(), nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_diff_sboms", map[string]any{
		"from_sbom_id": "s1",
		"to_sbom_id":   "s2",
		"offset":       99,
	})
	i.True(!res.IsError)
	i.True(strings.Contains(resultText(res), `"changes":[]`))
}

func TestDiffSBOMsNotFound(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		DiffSBOMsFn: func(context.Context, string, string) (client.ChangelogEntry, error) {
			return client.ChangelogEntry{}, client.ErrNotFound
		},
	}

	res := callTool(t, connect(t, api), "ocidex_diff_sboms", map[string]any{
		"from_sbom_id": "missing",
		"to_sbom_id":   "s2",
	})
	i.True(res.IsError)
	i.True(strings.Contains(resultText(res), "missing"))
}

func treeFixture() client.DiffTree {
	return client.DiffTree{
		From:    client.SBOMRef{Id: "s1"},
		To:      client.SBOMRef{Id: "s2"},
		Summary: client.ChangeSummary{Upgraded: 3},
		Nodes: sliceptr([]client.ComponentSummary{
			{
				Id: "n-base", Name: "base-image", BomRef: strptr("ref-base"), IsDirect: true,
				Version:           strptr("2.0"),
				DescendantChanges: &client.ChangeCounts{Upgraded: 3},
			},
			{
				Id: "n-tool", Name: "tool", BomRef: strptr("ref-tool"), IsDirect: true,
				Version:           strptr("1.0"),
				DescendantChanges: &client.ChangeCounts{},
			},
			{
				Id: "n-openssl", Name: "openssl", BomRef: strptr("ref-openssl"),
				Version:           strptr("3.0.2"),
				DescendantChanges: &client.ChangeCounts{Upgraded: 1},
			},
		}),
		Edges: sliceptr([]client.DependencyEdge{
			{From: "ref-base", To: "ref-openssl"},
		}),
		Roots: sliceptr([]string{"ref-tool", "ref-base"}),
		Changes: sliceptr([]client.ComponentDiff{
			{Direction: "upgraded", Name: "openssl", Type: "library", NodeRef: strptr("n-openssl"),
				PreviousVersion: strptr("3.0.1"), Version: strptr("3.0.2")},
		}),
	}
}

// Without a node the tool answers "which direct dependency should I look at",
// which means ordering by blast radius rather than by the order the API
// happened to return roots in.
func TestDiffTreeRootsOrderedByBlastRadius(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetDiffTreeFn: func(context.Context, string, string) (client.DiffTree, error) {
			return treeFixture(), nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_diff_tree", map[string]any{
		"from_sbom_id": "s1",
		"to_sbom_id":   "s2",
	})
	i.True(!res.IsError)

	text := resultText(res)
	i.True(strings.Index(text, "base-image") < strings.Index(text, `"tool"`))
	i.True(strings.Contains(text, `"total_descendant_changes":3`))
	// The render-oriented payload must not survive into the answer: raw edges
	// and bom-refs are what the summary exists to replace.
	i.True(!strings.Contains(text, "ref-base"))
}

// With a node the tool descends one level, reporting the node's own change and
// its children — the drill-down half of the acceptance criteria.
func TestDiffTreeDescendsIntoNode(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetDiffTreeFn: func(context.Context, string, string) (client.DiffTree, error) {
			return treeFixture(), nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_diff_tree", map[string]any{
		"from_sbom_id": "s1",
		"to_sbom_id":   "s2",
		"node":         "n-base",
	})
	i.True(!res.IsError)

	text := resultText(res)
	i.True(strings.Contains(text, "openssl"))
	i.True(strings.Contains(text, `"total_children":1`))

	// Descending into a node that itself changed reports that change too.
	res = callTool(t, connect(t, api), "ocidex_diff_tree", map[string]any{
		"from_sbom_id": "s1",
		"to_sbom_id":   "s2",
		"node":         "n-openssl",
	})
	i.True(!res.IsError)
	text = resultText(res)
	i.True(strings.Contains(text, `"node_change"`))
	i.True(strings.Contains(text, "3.0.1"))
}

func TestArtifactChangelog(t *testing.T) {
	i := is.New(t)
	var got client.GetArtifactChangelogParams
	api := &client.FakeClient{
		GetArtifactChangelogFn: func(_ context.Context, id string, params client.GetArtifactChangelogParams) (client.Changelog, error) {
			i.Equal(id, "art-1")
			got = params
			return client.Changelog{
				ArtifactId:             "art-1",
				ResolvedMode:           "semver",
				AvailableArchitectures: sliceptr([]string{"amd64", "arm64"}),
				Entries: sliceptr([]client.ChangelogEntry{{
					From:    client.SBOMRef{Id: "s1", SubjectVersion: strptr("1.0.0")},
					To:      client.SBOMRef{Id: "s2", SubjectVersion: strptr("1.1.0")},
					Summary: client.ChangeSummary{Upgraded: 2},
				}}),
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_artifact_changelog", map[string]any{
		"artifact_id": "art-1",
		"arch":        "amd64",
	})
	i.True(!res.IsError)
	i.Equal(*got.Arch, "amd64")
	i.True(got.Flavor == nil)

	text := resultText(res)
	i.True(strings.Contains(text, "semver"))
	i.True(strings.Contains(text, `"upgraded":2`))
	// The two ids are the drill-down into the diff tool, so they have to be in
	// the entry rather than only in the artifact's SBOM list.
	i.True(strings.Contains(text, `"id":"s1"`))
	i.True(strings.Contains(text, `"id":"s2"`))
}

func TestArtifactVulnerabilities(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetArtifactVulnSummaryFn: func(_ context.Context, artifactID string) (client.VulnSummary, error) {
			i.Equal(artifactID, "art-1")
			return client.VulnSummary{Critical: 1, High: 4, Total: 12}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_artifact_vulnerabilities", map[string]any{"artifact_id": "art-1"})
	i.True(!res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, `"critical":1`))
	i.True(strings.Contains(text, `"total":12`))
}

func TestComponentVulnerabilities(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetComponentVulnsFn: func(_ context.Context, componentID string) ([]client.ComponentVulnEntry, error) {
			i.Equal(componentID, "comp-1")
			return []client.ComponentVulnEntry{
				{CanonicalId: "CVE-2024-1", Severity: "critical", CvssScore: float32ptr(9.8), FixedVersion: strptr("3.0.2")},
				{CanonicalId: "CVE-2024-2", Severity: "low", Summary: strptr("minor issue")},
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_component_vulnerabilities", map[string]any{"component_id": "comp-1"})
	i.True(!res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, "CVE-2024-1"))
	i.True(strings.Contains(text, `"fixed_version":"3.0.2"`))
	// The unfixed advisory must come back without inventing a fixed version.
	i.True(strings.Contains(text, "CVE-2024-2"))
	i.True(strings.Count(text, "fixed_version") == 1)
}

func TestGetVulnerabilityListsAffectedArtifacts(t *testing.T) {
	i := is.New(t)
	var gotOpts client.PageOpts
	api := &client.FakeClient{
		GetVulnerabilityFn: func(_ context.Context, vulnID string, opts client.PageOpts) (client.GetVulnerabilityOutputBody, error) {
			i.Equal(vulnID, "CVE-2024-3094")
			gotOpts = opts
			return client.GetVulnerabilityOutputBody{
				Vulnerability: client.VulnDetail{
					CanonicalId: "CVE-2024-3094",
					Severity:    "critical",
					CvssScore:   float32ptr(10),
					Summary:     strptr("backdoor in xz"),
					Aliases:     sliceptr([]string{"GHSA-xxxx-yyyy-zzzz"}),
				},
				AffectedArtifacts: sliceptr([]client.AffectedArtifact{
					{Id: "art-1", Name: "ghcr.io/pfenerty/ocidex", AffectedSbomCount: 2},
				}),
				Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_get_vulnerability", map[string]any{"vuln_id": "CVE-2024-3094"})
	i.True(!res.IsError)
	i.Equal(gotOpts.Limit, int32(defaultSearchLimit))
	text := resultText(res)
	i.True(strings.Contains(text, "backdoor in xz"))
	i.True(strings.Contains(text, "ghcr.io/pfenerty/ocidex"))
	i.True(strings.Contains(text, "GHSA-xxxx-yyyy-zzzz"))
}

func TestIngestSBOM(t *testing.T) {
	i := is.New(t)
	var (
		gotData   []byte
		gotParams client.IngestSbomParams
	)
	api := &client.FakeClient{
		IngestSBOMFn: func(_ context.Context, data []byte, params client.IngestSbomParams) (client.IngestSBOMOutputBody, error) {
			gotData, gotParams = data, params
			return client.IngestSBOMOutputBody{Id: "s9", ComponentCount: 7, SpecVersion: "1.5"}, nil
		},
	}

	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`
	res := callTool(t, connect(t, api), "ocidex_ingest_sbom", map[string]any{
		"bom":     bom,
		"source":  "pfenerty/ci",
		"version": "1.2.3",
	})
	i.True(!res.IsError)

	// The document has to reach the API byte for byte — re-encoding it here
	// would change what gets stored.
	i.Equal(string(gotData), bom)
	i.True(json.Valid(gotData))
	i.Equal(*gotParams.Source, "pfenerty/ci")
	i.Equal(*gotParams.Version, "1.2.3")
	i.True(gotParams.Digest == nil)
	i.True(strings.Contains(resultText(res), "s9"))
}

// A read-only key is the predictable way for the one write tool to fail, and
// the message has to name the scope and the fix rather than say "forbidden".
func TestIngestSBOMOnReadOnlyKey(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		IngestSBOMFn: func(context.Context, []byte, client.IngestSbomParams) (client.IngestSBOMOutputBody, error) {
			return client.IngestSBOMOutputBody{}, client.ErrForbidden
		},
	}

	res := callTool(t, connect(t, api), "ocidex_ingest_sbom", map[string]any{
		"bom":    `{"bomFormat":"CycloneDX"}`,
		"source": "pfenerty/ci",
	})
	i.True(res.IsError)
	text := resultText(res)
	i.True(strings.Contains(text, "read-write"))
	i.True(strings.Contains(text, "ocidex-cli login"))
}

func TestIngestSBOMRequiresDocument(t *testing.T) {
	i := is.New(t)
	var called bool
	api := &client.FakeClient{
		IngestSBOMFn: func(context.Context, []byte, client.IngestSbomParams) (client.IngestSBOMOutputBody, error) {
			called = true
			return client.IngestSBOMOutputBody{}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_ingest_sbom", map[string]any{"bom": "", "source": "pfenerty/ci"})
	i.True(res.IsError)
	i.True(!called)
}

// The write tool must be visibly a write: a client that gates writes reads the
// annotation, not the description.
func TestIngestToolIsAnnotatedAsAWrite(t *testing.T) {
	i := is.New(t)
	session := connect(t, &client.FakeClient{})
	tools, err := session.ListTools(t.Context(), nil)
	i.NoErr(err)

	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "ocidex_ingest_sbom" {
			continue
		}
		found = true
		i.True(tool.Annotations != nil)
		i.True(!tool.Annotations.ReadOnlyHint)
	}
	i.True(found)
}
