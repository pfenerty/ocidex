package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newArtifactCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "artifact",
		Aliases: []string{"artifacts"},
		Short:   "Work with tracked artifacts",
	}
	cmd.AddCommand(
		newArtifactListCmd(cfg),
		newArtifactGetCmd(cfg),
		newArtifactChangelogCmd(cfg),
		newArtifactLicenseSummaryCmd(cfg),
	)
	return cmd
}

func artifactColumns() []output.Column[client.ArtifactSummary] {
	return []output.Column[client.ArtifactSummary]{
		{Header: "ID", Value: func(a client.ArtifactSummary) string { return a.Id }},
		{Header: colType, Value: func(a client.ArtifactSummary) string { return a.Type }},
		{Header: colName, Value: func(a client.ArtifactSummary) string { return qualifiedName(a.Group, a.Name) }},
		{Header: "SBOMS", Value: func(a client.ArtifactSummary) string {
			// Both numbers matter: an artifact with SBOMs none of which are
			// sufficient looks tracked but answers no questions.
			return fmt.Sprintf("%d/%d", a.SufficientSbomCount, a.SbomCount)
		}},
		{Header: "SIGNING", Value: func(a client.ArtifactSummary) string { return a.SigningStatus }},
	}
}

func newArtifactListCmd(cfg *rootConfig) *cobra.Command {
	var filter client.ArtifactFilter
	var limit, offset int32

	cmd := &cobra.Command{
		Use:   verbList,
		Short: "List tracked artifacts",
		Long: `List tracked artifacts.

The SBOMS column reads sufficient/total: the server hides artifacts with no
sufficiently enriched SBOM unless --include-insufficient is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			page, err := cfg.api.ListArtifacts(cmd.Context(), filter, client.PageOpts{Limit: limit, Offset: offset})
			if err != nil {
				return fmt.Errorf("listing artifacts: %w", err)
			}
			if err := output.List(cmd.OutOrStdout(), cfg.format, page.Data, artifactColumns()...); err != nil {
				return err
			}
			if cfg.format == output.Table && page.Pagination.HasMore {
				fmt.Fprintf(cmd.ErrOrStderr(), "\n%d shown; more available (use --offset %d)\n",
					len(page.Data), int(offset)+len(page.Data))
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&filter.Type, "type", "", "filter by CycloneDX type, e.g. container or application")
	f.StringVar(&filter.Name, "name", "", "filter by artifact name")
	f.BoolVar(&filter.IncludeInsufficient, "include-insufficient", false,
		"also list artifacts whose SBOMs are not sufficiently enriched")
	f.Int32Var(&limit, "limit", 0, "maximum artifacts to return (server default 50)")
	f.Int32Var(&offset, "offset", 0, "index of the first artifact to return")
	return cmd
}

func newArtifactGetCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   verbGet,
		Short: "Show one artifact in full",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			artifact, err := cfg.api.GetArtifact(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("getting artifact: %w", err)
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, artifact)
		},
	}
}

func newArtifactChangelogCmd(cfg *rootConfig) *cobra.Command {
	var params client.GetArtifactChangelogParams
	var subjectVersion, arch, flavor string

	cmd := &cobra.Command{
		Use:   "changelog <id>",
		Short: "Show what changed between successive versions of an artifact",
		Long: `Show what changed between successive versions of an artifact.

An artifact usually has several SBOMs per version — one per architecture and
flavor — so a changelog only means something once that axis is pinned. Pass
--arch and --flavor when the artifact has more than one; the available values
are printed to stderr in table mode.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params.SubjectVersion = optional(subjectVersion)
			params.Arch = optional(arch)
			params.Flavor = optional(flavor)

			log, err := cfg.api.GetArtifactChangelog(cmd.Context(), args[0], params)
			if err != nil {
				return fmt.Errorf("getting changelog: %w", err)
			}
			if cfg.format != output.Table {
				return output.Item(cmd.OutOrStdout(), cfg.format, log)
			}
			renderChangelog(cmd.OutOrStdout(), log)
			printChangelogAxes(cmd.ErrOrStderr(), log)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&subjectVersion, "subject-version", "", "compare only within this version")
	f.StringVar(&arch, "arch", "", "architecture to follow, e.g. amd64")
	f.StringVar(&flavor, "flavor", "", "image flavor to follow, e.g. distroless")
	return cmd
}

// renderChangelog prints one block per version transition. A flat table would
// lose the pairing, which is the only thing that makes a change legible.
func renderChangelog(w io.Writer, log client.Changelog) {
	entries := derefSlice(log.Entries)
	if len(entries) == 0 {
		fmt.Fprintln(w, "(no version transitions recorded for this artifact)")
		return
	}
	for i, e := range entries {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s -> %s\n", sbomRefLabel(e.From), sbomRefLabel(e.To))
		fmt.Fprintf(w, "  %s\n", summaryLine(e.Summary))
		for _, c := range derefSlice(e.Changes) {
			fmt.Fprintf(w, "  %s %-9s %s%s\n",
				changeMark(&c), c.Direction, qualifiedName(c.Group, c.Name), versionMove(c))
		}
	}
}

func sbomRefLabel(r client.SBOMRef) string {
	label := deref(r.SubjectVersion)
	if label == "" {
		label = r.Id
	}
	var qual []string
	if a := deref(r.Architecture); a != "" {
		qual = append(qual, a)
	}
	if f := deref(r.Flavor); f != "" {
		qual = append(qual, f)
	}
	if len(qual) > 0 {
		label += " (" + strings.Join(qual, "/") + ")"
	}
	return label + " " + r.CreatedAt.Format(time.RFC3339)
}

func versionMove(c client.ComponentDiff) string {
	from, to := deref(c.PreviousVersion), deref(c.Version)
	switch {
	case from != "" && to != "":
		return fmt.Sprintf(" %s -> %s", from, to)
	case to != "":
		return " " + to
	case from != "":
		return " " + from
	default:
		return ""
	}
}

// printChangelogAxes tells the reader which --arch and --flavor values exist,
// since an unpinned changelog silently follows only one of them.
func printChangelogAxes(w io.Writer, log client.Changelog) {
	fmt.Fprintf(w, "\nmode: %s", log.ResolvedMode)
	if !log.HasSemver {
		fmt.Fprint(w, " (no semver versions; ordered by ingest time)")
	}
	fmt.Fprintln(w)
	if a := derefSlice(log.AvailableArchitectures); len(a) > 1 {
		fmt.Fprintf(w, "architectures: %s\n", strings.Join(a, ", "))
	}
	if f := derefSlice(log.AvailableFlavors); len(f) > 1 {
		fmt.Fprintf(w, "flavors: %s\n", strings.Join(f, ", "))
	}
}

func licenseColumns() []output.Column[client.LicenseCount] {
	return []output.Column[client.LicenseCount]{
		{Header: "LICENSE", Value: func(l client.LicenseCount) string {
			if id := deref(l.SpdxId); id != "" {
				return id
			}
			return l.Name
		}},
		{Header: "CATEGORY", Value: func(l client.LicenseCount) string { return l.Category }},
		{Header: "COMPONENTS", Value: func(l client.LicenseCount) string {
			return fmt.Sprint(l.ComponentCount)
		}},
	}
}

func newArtifactLicenseSummaryCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:     "license-summary <id>",
		Aliases: []string{"licenses"},
		Short:   "Count components by license across an artifact's latest SBOM",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := cfg.api.GetArtifactLicenseSummary(cmd.Context(), args[0])
			if err != nil {
				return fmt.Errorf("getting license summary: %w", err)
			}
			return output.List(cmd.OutOrStdout(), cfg.format, derefSlice(out.Licenses), licenseColumns()...)
		},
	}
}
