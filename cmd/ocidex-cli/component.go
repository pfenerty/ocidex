package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newComponentCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "component",
		Aliases: []string{"components"},
		Short:   "Search the packages found inside SBOMs",
		Long: `Search the packages found inside SBOMs.

There are two views of the same data, because the server offers two and they
answer different questions. ` + "`list`" + ` is deduplicated: one row per distinct
package, with the number of SBOMs it appears in — use it to browse. ` + "`search`" + `
is per-occurrence: one row per SBOM a named package appears in, with the version
that SBOM carries — use it to answer "who ships the vulnerable version".`,
	}
	cmd.AddCommand(
		newComponentListCmd(cfg),
		newComponentSearchCmd(cfg),
		newComponentGetCmd(cfg),
		newComponentVersionsCmd(cfg),
		newComponentPurlTypesCmd(cfg),
	)
	return cmd
}

func distinctComponentColumns() []output.Column[client.DistinctComponentSummary] {
	return []output.Column[client.DistinctComponentSummary]{
		{Header: colName, Value: func(c client.DistinctComponentSummary) string {
			return qualifiedName(c.Group, c.Name)
		}},
		{Header: colType, Value: func(c client.DistinctComponentSummary) string { return c.Type }},
		{Header: "PURL TYPES", Value: func(c client.DistinctComponentSummary) string {
			return strings.Join(derefSlice(c.PurlTypes), ",")
		}},
		{Header: "VERSIONS", Value: func(c client.DistinctComponentSummary) string {
			return fmt.Sprint(c.VersionCount)
		}},
		{Header: "SBOMS", Value: func(c client.DistinctComponentSummary) string {
			return fmt.Sprint(c.SbomCount)
		}},
	}
}

func newComponentListCmd(cfg *rootConfig) *cobra.Command {
	var filter client.DistinctComponentFilter
	var limit, offset int32

	cmd := &cobra.Command{
		Use:   verbList,
		Short: "Browse distinct packages across every visible SBOM",
		Long: `Browse distinct packages across every visible SBOM.

One row per distinct package, not per occurrence: VERSIONS and SBOMS say how
many of each are behind it. Run ` + "`component purl-types`" + ` for the values
--purl-type accepts.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			page, err := cfg.api.SearchDistinctComponents(cmd.Context(), filter,
				client.PageOpts{Limit: limit, Offset: offset})
			if err != nil {
				return fmt.Errorf("listing components: %w", err)
			}
			if err := output.List(cmd.OutOrStdout(), cfg.format, page.Data, distinctComponentColumns()...); err != nil {
				return err
			}
			printPageHint(cmd, cfg, len(page.Data), offset, page.Pagination.Total)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&filter.Name, "name", "", "filter by package name (substring match)")
	f.StringVar(&filter.Group, "group", "", "filter by package group, e.g. a Maven groupId")
	f.StringVar(&filter.Type, "type", "", "filter by CycloneDX component type, e.g. library")
	f.StringVar(&filter.PurlType, "purl-type", "", "filter by purl type, e.g. golang, npm, deb")
	f.StringVar(&filter.Sort, "sort", "", "sort field (server default: name)")
	f.StringVar(&filter.SortDir, "sort-dir", "", "sort direction: asc or desc")
	f.Int32Var(&limit, "limit", 0, "maximum packages to return (server default 50)")
	f.Int32Var(&offset, "offset", 0, "index of the first package to return")
	return cmd
}

func componentColumns() []output.Column[client.ComponentSummary] {
	return []output.Column[client.ComponentSummary]{
		{Header: "ID", Value: func(c client.ComponentSummary) string { return c.Id }},
		{Header: colName, Value: func(c client.ComponentSummary) string {
			return qualifiedName(c.Group, c.Name)
		}},
		{Header: "VERSION", Value: func(c client.ComponentSummary) string { return deref(c.Version) }},
		{Header: "SBOM", Value: func(c client.ComponentSummary) string { return c.SbomId }},
		{Header: "VULNS", Value: func(c client.ComponentSummary) string { return derefInt(c.VulnCount) }},
		{Header: "MAX SEVERITY", Value: func(c client.ComponentSummary) string { return deref(c.MaxSeverity) }},
	}
}

func newComponentSearchCmd(cfg *rootConfig) *cobra.Command {
	var filter client.ComponentFilter
	var limit, offset int32

	cmd := &cobra.Command{
		Use:   "search <name>",
		Short: "Find every SBOM a named package appears in",
		Long: `Find every SBOM a named package appears in.

One row per occurrence, so the same package appears once per SBOM that carries
it, with that SBOM's version. The name is matched by the server, not globbed
here.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filter.Name = args[0]
			page, err := cfg.api.SearchComponents(cmd.Context(), filter,
				client.PageOpts{Limit: limit, Offset: offset})
			if err != nil {
				return fmt.Errorf("searching components: %w", err)
			}
			if err := output.List(cmd.OutOrStdout(), cfg.format, page.Data, componentColumns()...); err != nil {
				return err
			}
			printPageHint(cmd, cfg, len(page.Data), offset, page.Pagination.Total)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&filter.Group, "group", "", "filter by package group, e.g. a Maven groupId")
	f.StringVar(&filter.Version, "version", "", "filter to one version")
	f.Int32Var(&limit, "limit", 0, "maximum occurrences to return (server default 50)")
	f.Int32Var(&offset, "offset", 0, "index of the first occurrence to return")
	return cmd
}

func newComponentGetCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show one package occurrence in full",
		Long: `Show one package occurrence in full.

The id is a component id from ` + "`component search`" + `, which identifies the
package inside one SBOM — hashes, licenses, and external references are all
that SBOM's view of it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := cfg.api.GetComponent(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("getting component: %w", err)
			}
			if cfg.format != output.Table {
				return output.Item(cmd.OutOrStdout(), cfg.format, c)
			}
			renderComponent(cmd.OutOrStdout(), c)
			return nil
		},
	}
}

// renderComponent prints the scalar fields as a key/value block and then the
// three lists. output.Item would flatten the lists into unreadable cells, and
// they are the reason to look a component up in the first place.
func renderComponent(w io.Writer, c client.ComponentDetail) {
	_ = output.Item(w, output.Table, c,
		output.Column[client.ComponentDetail]{Header: "ID", Value: func(c client.ComponentDetail) string { return c.Id }},
		output.Column[client.ComponentDetail]{Header: colName, Value: func(c client.ComponentDetail) string {
			return qualifiedName(c.Group, c.Name)
		}},
		output.Column[client.ComponentDetail]{Header: "VERSION", Value: func(c client.ComponentDetail) string { return deref(c.Version) }},
		output.Column[client.ComponentDetail]{Header: colType, Value: func(c client.ComponentDetail) string { return c.Type }},
		output.Column[client.ComponentDetail]{Header: "PURL", Value: func(c client.ComponentDetail) string { return deref(c.Purl) }},
		output.Column[client.ComponentDetail]{Header: "CPE", Value: func(c client.ComponentDetail) string { return deref(c.Cpe) }},
		output.Column[client.ComponentDetail]{Header: "SBOM", Value: func(c client.ComponentDetail) string { return c.SbomId }},
		output.Column[client.ComponentDetail]{Header: "PUBLISHER", Value: func(c client.ComponentDetail) string { return deref(c.Publisher) }},
		output.Column[client.ComponentDetail]{Header: "FOUND BY", Value: func(c client.ComponentDetail) string { return deref(c.FoundBy) }},
		output.Column[client.ComponentDetail]{Header: "VULNS", Value: func(c client.ComponentDetail) string { return derefInt(c.VulnCount) }},
	)

	for _, l := range derefSlice(c.Licenses) {
		fmt.Fprintf(w, "license:  %s\n", licenseLabel(l))
	}
	for _, h := range derefSlice(c.Hashes) {
		fmt.Fprintf(w, "hash:     %s:%s\n", h.Algorithm, h.Value)
	}
	for _, r := range derefSlice(c.ExternalReferences) {
		fmt.Fprintf(w, "ref:      %-12s %s\n", r.Type, r.Url)
	}
}

// licenseLabel prefers the SPDX id, because that is what tooling matches on,
// and falls back to the declared name so a non-SPDX license is not blank.
func licenseLabel(l client.LicenseSummary) string {
	if id := deref(l.SpdxId); id != "" {
		return id
	}
	return deref(l.Name)
}

func componentVersionColumns() []output.Column[client.ComponentVersionEntry] {
	return []output.Column[client.ComponentVersionEntry]{
		{Header: "VERSION", Value: func(v client.ComponentVersionEntry) string { return deref(v.Version) }},
		{Header: "ARTIFACT", Value: func(v client.ComponentVersionEntry) string { return deref(v.ArtifactName) }},
		{Header: "SUBJECT VERSION", Value: func(v client.ComponentVersionEntry) string { return deref(v.SubjectVersion) }},
		{Header: "ARCH", Value: func(v client.ComponentVersionEntry) string { return deref(v.Architecture) }},
		{Header: "VULNS", Value: func(v client.ComponentVersionEntry) string { return fmt.Sprint(v.VulnCount) }},
		{Header: "MAX SEVERITY", Value: func(v client.ComponentVersionEntry) string { return deref(v.MaxSeverity) }},
	}
}

func newComponentVersionsCmd(cfg *rootConfig) *cobra.Command {
	var params client.GetComponentVersionsParams
	var group, version, typ string

	cmd := &cobra.Command{
		Use:   "versions <name>",
		Short: "Show which version of a package each artifact carries",
		Long: `Show which version of a package each artifact carries.

This is the drift question: one row per artifact shipping the named package,
with the version it has. Unpaginated — the server returns the whole set.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Name = args[0]
			params.Group = optional(group)
			params.Version = optional(version)
			params.Type = optional(typ)

			out, err := cfg.api.GetComponentVersions(cmd.Context(), params)
			if err != nil {
				return fmt.Errorf("getting component versions: %w", err)
			}
			return output.List(cmd.OutOrStdout(), cfg.format, derefSlice(out.Versions), componentVersionColumns()...)
		},
	}

	f := cmd.Flags()
	f.StringVar(&group, "group", "", "filter by package group, e.g. a Maven groupId")
	f.StringVar(&version, "version", "", "filter to one version")
	f.StringVar(&typ, "type", "", "filter by CycloneDX component type, e.g. library")
	return cmd
}

func newComponentPurlTypesCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "purl-types",
		Short: "List the purl types present in visible SBOMs",
		Long: `List the purl types present in visible SBOMs.

These are the values ` + "`component list --purl-type`" + ` accepts; they depend
on what has actually been ingested, not on a fixed vocabulary.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			types, err := cfg.api.ListComponentPurlTypes(cmd.Context())
			if err != nil {
				return fmt.Errorf("listing purl types: %w", err)
			}
			if cfg.format != output.Table {
				return output.Item(cmd.OutOrStdout(), cfg.format, types)
			}
			for _, t := range types {
				fmt.Fprintln(cmd.OutOrStdout(), t)
			}
			return nil
		},
	}
}
