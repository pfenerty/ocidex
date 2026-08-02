package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

func ptr[T any](v T) *T { return &v }

func testChangelogEntry() client.ChangelogEntry {
	return client.ChangelogEntry{
		From: client.SBOMRef{Id: "from-id", CreatedAt: time.Now()},
		To:   client.SBOMRef{Id: "to-id", CreatedAt: time.Now()},
		Summary: client.ChangeSummary{
			Added: 1, Removed: 0, Upgraded: 1, Downgraded: 0, Modified: 0,
		},
		Changes: &[]client.ComponentDiff{
			{Direction: "added", Type: "library", Name: "zlib", Version: ptr("1.3")},
			{
				Direction: "upgraded", Type: "library", Name: "openssl",
				Group: ptr("org.openssl"), Version: ptr("3.2.1"), PreviousVersion: ptr("3.2.0"),
			},
		},
	}
}

func TestSBOMDiffTable(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		DiffSBOMsFn: func(_ context.Context, from, to string) (client.ChangelogEntry, error) {
			is.Equal(from, "from-id")
			is.Equal(to, "to-id")
			return testChangelogEntry(), nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "sbom", "diff", "--from", "from-id", "--to", "to-id")
	is.NoErr(err)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 3) // header + two changes
	is.True(strings.Contains(lines[0], "CHANGE"))
	is.True(strings.Contains(lines[2], "org.openssl/openssl"))
	is.True(strings.Contains(lines[2], "3.2.0"))
	// The tally is a human aid, so it stays out of the piped table.
	is.True(strings.Contains(stderr, "+1 added"))
	is.True(!strings.Contains(stdout, "+1 added"))
}

// -o json emits the whole entry, not just the change list: the two SBOM
// references and the summary are what make it interpretable later.
func TestSBOMDiffJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		DiffSBOMsFn: func(context.Context, string, string) (client.ChangelogEntry, error) {
			return testChangelogEntry(), nil
		},
	}

	stdout, _, err := runCLI(t, fake, "sbom", "diff", "--from", "a", "--to", "b", "-o", "json")
	is.NoErr(err)

	var got client.ChangelogEntry
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.From.Id, "from-id")
	is.Equal(got.Summary.Upgraded, int64(1))
	is.Equal(len(*got.Changes), 2)
}

func TestSBOMDiffRequiresBothRefs(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		DiffSBOMsFn: func(context.Context, string, string) (client.ChangelogEntry, error) {
			t.Fatal("diff must not run without --to")
			return client.ChangelogEntry{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "sbom", "diff", "--from", "a")
	is.True(err != nil)
	is.Equal(exitCode(err, false), exitUsage)
}

// testDiffTree: app -> openssl -> zlib, with zlib upgraded. The change is on
// the leaf, so openssl carries a descendant count and app carries one too.
func testDiffTree() client.DiffTree {
	return client.DiffTree{
		From:    client.SBOMRef{Id: "from-id", CreatedAt: time.Now()},
		To:      client.SBOMRef{Id: "to-id", CreatedAt: time.Now()},
		Summary: client.ChangeSummary{Upgraded: 1},
		Roots:   &[]string{"ref-app"},
		Nodes: &[]client.ComponentSummary{
			{
				Id: "id-app", BomRef: ptr("ref-app"), Name: "app", Type: "application",
				Version: ptr("1.0.0"), IsDirect: true,
				DescendantChanges: &client.ChangeCounts{Upgraded: 1},
			},
			{
				Id: "id-openssl", BomRef: ptr("ref-openssl"), Name: "openssl", Type: "library",
				Group: ptr("org.openssl"), Version: ptr("3.2.1"),
				DescendantChanges: &client.ChangeCounts{Upgraded: 1},
			},
			{
				Id: "id-zlib", BomRef: ptr("ref-zlib"), Name: "zlib", Type: "library",
				Version: ptr("1.3"),
			},
			{
				Id: "id-quiet", BomRef: ptr("ref-quiet"), Name: "quiet", Type: "library",
				Version: ptr("2.0"),
			},
		},
		Edges: &[]client.DependencyEdge{
			{From: "ref-app", To: "ref-openssl"},
			{From: "ref-app", To: "ref-quiet"},
			{From: "ref-openssl", To: "ref-zlib"},
		},
		Changes: &[]client.ComponentDiff{
			{
				Direction: "upgraded", Type: "library", Name: "zlib",
				Version: ptr("1.3"), PreviousVersion: ptr("1.2.13"), NodeRef: ptr("id-zlib"),
			},
		},
	}
}

func TestSBOMDiffTreeTable(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetDiffTreeFn: func(context.Context, string, string) (client.DiffTree, error) {
			return testDiffTree(), nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "sbom", "diff-tree", "--from", "a", "--to", "b")
	is.NoErr(err)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 4) // app, openssl, zlib, quiet

	// Depth is indentation, and children are sorted by name.
	is.True(strings.HasPrefix(lines[0], "  app@1.0.0")) // leading blank change mark
	is.True(strings.Contains(lines[0], "[1 below]"))
	is.True(strings.HasPrefix(lines[1], "    org.openssl/openssl@3.2.1"))
	is.True(strings.HasPrefix(lines[2], "    ~ zlib@1.3"))
	is.True(strings.Contains(lines[2], "was 1.2.13"))
	is.True(strings.HasPrefix(lines[3], "    quiet@2.0"))

	is.True(strings.Contains(stderr, "^1 upgraded"))
}

// --changed-only prunes using the server's descendantChanges rather than
// re-deriving what changed underneath each node.
func TestSBOMDiffTreeChangedOnly(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetDiffTreeFn: func(context.Context, string, string) (client.DiffTree, error) {
			return testDiffTree(), nil
		},
	}

	stdout, _, err := runCLI(t, fake, "sbom", "diff-tree", "--from", "a", "--to", "b", "--changed-only")
	is.NoErr(err)
	is.True(strings.Contains(stdout, "zlib"))
	is.True(!strings.Contains(stdout, "quiet"))
}

// A cycle in a malformed BOM must not hang the walk.
func TestSBOMDiffTreeCycle(t *testing.T) {
	is := is.New(t)
	tree := testDiffTree()
	edges := append(*tree.Edges, client.DependencyEdge{From: "ref-zlib", To: "ref-app"})
	tree.Edges = &edges

	fake := &client.FakeClient{
		GetDiffTreeFn: func(context.Context, string, string) (client.DiffTree, error) { return tree, nil },
	}

	stdout, _, err := runCLI(t, fake, "sbom", "diff-tree", "--from", "a", "--to", "b")
	is.NoErr(err)
	is.True(strings.Contains(stdout, "(cycle)"))
}

func TestSBOMDiffTreeEmpty(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetDiffTreeFn: func(context.Context, string, string) (client.DiffTree, error) {
			return client.DiffTree{Summary: client.ChangeSummary{}}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "sbom", "diff-tree", "--from", "a", "--to", "b")
	is.NoErr(err)
	is.True(strings.Contains(stdout, "no dependency tree"))
}
