package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

// diffRefs holds the two SBOM ids every diff command compares.
type diffRefs struct{ from, to string }

func (d *diffRefs) bind(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&d.from, "from", "", "SBOM to compare from (required)")
	f.StringVar(&d.to, "to", "", "SBOM to compare to (required)")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")
}

func newSBOMDiffCmd(cfg *rootConfig) *cobra.Command {
	refs := &diffRefs{}

	cmd := &cobra.Command{
		Use:   "diff --from <id> --to <id>",
		Short: "Show what changed between two SBOMs",
		Long: `Show what changed between two SBOMs.

In table mode the change list goes to stdout and the tally to stderr, so the
table survives a pipe. -o json and -o yaml emit the whole changelog entry,
including the two SBOM references and the summary.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entry, err := cfg.api.DiffSBOMs(cmd.Context(), refs.from, refs.to)
			if err != nil {
				return fmt.Errorf("diffing SBOMs: %w", err)
			}
			if cfg.format != output.Table {
				return output.Item(cmd.OutOrStdout(), cfg.format, entry)
			}
			if err := output.List(cmd.OutOrStdout(), output.Table, derefSlice(entry.Changes), diffColumns()...); err != nil {
				return err
			}
			fmt.Fprint(cmd.ErrOrStderr(), "\n"+summaryLine(entry.Summary)+"\n")
			return nil
		},
	}

	refs.bind(cmd)
	return cmd
}

func newSBOMDiffTreeCmd(cfg *rootConfig) *cobra.Command {
	refs := &diffRefs{}
	var changedOnly bool

	cmd := &cobra.Command{
		Use:   "diff-tree --from <id> --to <id>",
		Short: "Show what changed between two SBOMs, as a dependency tree",
		Long: `Show what changed between two SBOMs, as a dependency tree.

The tree is the server's: roots, direct/transitive placement, and the per-node
descendant change counts are all computed there (ADR-021), so this renders and
does not recompute. A node is marked +, -, or ~ for added, removed, or changed,
and a node with unchanged descendants that themselves changed is annotated with
the counts underneath it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tree, err := cfg.api.GetDiffTree(cmd.Context(), refs.from, refs.to)
			if err != nil {
				return fmt.Errorf("diffing SBOMs: %w", err)
			}
			if cfg.format != output.Table {
				return output.Item(cmd.OutOrStdout(), cfg.format, tree)
			}
			renderDiffTree(cmd.OutOrStdout(), tree, changedOnly)
			fmt.Fprint(cmd.ErrOrStderr(), "\n"+summaryLine(tree.Summary)+"\n")
			return nil
		},
	}

	refs.bind(cmd)
	cmd.Flags().BoolVar(&changedOnly, "changed-only", false,
		"prune branches with no change anywhere beneath them")
	return cmd
}

func diffColumns() []output.Column[client.ComponentDiff] {
	return []output.Column[client.ComponentDiff]{
		{Header: "CHANGE", Value: func(d client.ComponentDiff) string { return d.Direction }},
		{Header: colType, Value: func(d client.ComponentDiff) string { return d.Type }},
		{Header: colName, Value: func(d client.ComponentDiff) string { return qualifiedName(d.Group, d.Name) }},
		{Header: "FROM", Value: func(d client.ComponentDiff) string { return deref(d.PreviousVersion) }},
		{Header: "TO", Value: func(d client.ComponentDiff) string { return deref(d.Version) }},
	}
}

func qualifiedName(group *string, name string) string {
	if g := deref(group); g != "" {
		return g + "/" + name
	}
	return name
}

// summaryLine is the one-line tally both diff commands end with.
func summaryLine(s client.ChangeSummary) string {
	return fmt.Sprintf("+%d added  -%d removed  ^%d upgraded  v%d downgraded  ~%d modified",
		s.Added, s.Removed, s.Upgraded, s.Downgraded, s.Modified)
}

// treeNode is one node ready to print: the server's component plus the change
// that landed on it, if any.
type treeNode struct {
	node   client.ComponentSummary
	change *client.ComponentDiff
}

// renderDiffTree walks the server's roots and edges. Edges and roots are
// bom-refs; changes point at nodes by id through nodeRef (ADR-021), so the two
// are joined here rather than re-derived.
func renderDiffTree(w io.Writer, tree client.DiffTree, changedOnly bool) {
	byRef := make(map[string]treeNode, len(derefSlice(tree.Nodes)))
	byID := make(map[string]string, len(derefSlice(tree.Nodes)))
	for _, n := range derefSlice(tree.Nodes) {
		if ref := deref(n.BomRef); ref != "" {
			byRef[ref] = treeNode{node: n}
			byID[n.Id] = ref
		}
	}
	for i, c := range derefSlice(tree.Changes) {
		ref, ok := byID[deref(c.NodeRef)]
		if !ok {
			continue
		}
		if tn, ok := byRef[ref]; ok {
			tn.change = &derefSlice(tree.Changes)[i]
			byRef[ref] = tn
		}
	}

	children := make(map[string][]string, len(derefSlice(tree.Edges)))
	for _, e := range derefSlice(tree.Edges) {
		children[e.From] = append(children[e.From], e.To)
	}

	roots := derefSlice(tree.Roots)
	if len(roots) == 0 {
		fmt.Fprintln(w, "(no dependency tree recorded for this SBOM)")
		return
	}

	// A component can appear under several parents, and a malformed BOM can
	// even contain a cycle; the path set keeps the walk finite either way.
	onPath := make(map[string]bool, len(byRef))
	for _, root := range roots {
		walkDiffTree(w, root, 0, byRef, children, onPath, changedOnly)
	}
}

func walkDiffTree(w io.Writer, ref string, depth int, byRef map[string]treeNode,
	children map[string][]string, onPath map[string]bool, changedOnly bool,
) {
	if onPath[ref] {
		fmt.Fprintf(w, "%s%s (cycle)\n", strings.Repeat("  ", depth), ref)
		return
	}
	tn, known := byRef[ref]
	if !known {
		return
	}
	if changedOnly && !subtreeChanged(tn) {
		return
	}

	fmt.Fprintf(w, "%s%s %s\n", strings.Repeat("  ", depth), changeMark(tn.change), nodeLabel(tn))

	onPath[ref] = true
	kids := append([]string(nil), children[ref]...)
	sort.Slice(kids, func(i, j int) bool {
		return byRef[kids[i]].node.Name < byRef[kids[j]].node.Name
	})
	for _, child := range kids {
		walkDiffTree(w, child, depth+1, byRef, children, onPath, changedOnly)
	}
	delete(onPath, ref)
}

// subtreeChanged uses the server's descendantChanges rather than walking the
// subtree, which is the whole point of ADR-021 computing them.
func subtreeChanged(tn treeNode) bool {
	if tn.change != nil {
		return true
	}
	d := tn.node.DescendantChanges
	if d == nil {
		return false
	}
	return d.Added+d.Removed+d.Upgraded+d.Downgraded+d.Modified > 0
}

// The server's ComponentDiff.Direction values. Upgraded, downgraded and
// modified all render the same way here, so only these two are named.
const (
	dirAdded   = "added"
	dirRemoved = "removed"
)

// changeMark is the leading glyph: what happened to this node itself.
func changeMark(c *client.ComponentDiff) string {
	if c == nil {
		return " "
	}
	switch c.Direction {
	case dirAdded:
		return "+"
	case dirRemoved:
		return "-"
	default:
		return "~"
	}
}

func nodeLabel(tn treeNode) string {
	var b strings.Builder
	b.WriteString(qualifiedName(tn.node.Group, tn.node.Name))
	if v := deref(tn.node.Version); v != "" {
		b.WriteString("@" + v)
	}
	if tn.change != nil {
		if prev := deref(tn.change.PreviousVersion); prev != "" {
			b.WriteString(" (was " + prev + ")")
		}
	}
	if d := tn.node.DescendantChanges; d != nil {
		if n := d.Added + d.Removed + d.Upgraded + d.Downgraded + d.Modified; n > 0 {
			fmt.Fprintf(&b, "  [%d below]", n)
		}
	}
	return b.String()
}

// derefSlice unwraps the optional slices the generated types use, so a nil
// pointer and an empty list are the same thing to render.
func derefSlice[T any](s *[]T) []T {
	if s == nil {
		return nil
	}
	return *s
}
