package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newSBOMCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Work with SBOMs",
	}
	cmd.AddCommand(
		newSBOMPushCmd(cfg),
		newSBOMListCmd(cfg),
		newSBOMGetCmd(cfg),
		newSBOMDeleteCmd(cfg),
		newSBOMDiffCmd(cfg),
		newSBOMDiffTreeCmd(cfg),
	)
	return cmd
}

// pushOpts mirrors the ingest query parameters the CLI exposes.
type pushOpts struct {
	source       string
	artifactFile string
	digest       string
	subjectType  string
	subjectName  string
	subjectGroup string
	subjectPurl  string
	version      string
	versionFile  string
	arch         string
	archFile     string
}

func newSBOMPushCmd(cfg *rootConfig) *cobra.Command {
	o := &pushOpts{}

	cmd := &cobra.Command{
		Use: "push <sbom-file>",
		// The endpoint is called ingest and the issue that specified this
		// command called it ingest; the Tekton task and ADR-029 both say push.
		// The alias costs nothing and spares anyone who learned the other word.
		Aliases: []string{"ingest"},
		Short:   "Upload a CycloneDX SBOM",
		Long: `Upload a CycloneDX SBOM for a build artifact.

The SBOM lands in the namespace that owns --source. For a non-container subject
the server requires the subject to be declared rather than inferred, because a
` + "`syft dir:`" + ` scan describes the directory it scanned, not the thing you built.

Authentication is via the OCIDEX_API_KEY environment variable, or the api-key
key in ~/.config/ocidex/config.yaml.`,
		Example: `  ocidex-cli sbom push ./ocidex.cdx.json \
    --source myorg/ci \
    --artifact-file ./bin/ocidex \
    --subject-type application \
    --subject-name ocidex \
    --subject-purl pkg:golang/github.com/pfenerty/ocidex@v1.2.3 \
    --version v1.2.3 \
    --arch amd64`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOMPush(cmd, cfg, o, args[0])
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.source, "source", "", "ingest source: UUID or <namespace>/<name> (required)")
	f.StringVar(&o.artifactFile, "artifact-file", "", "artifact the SBOM describes; its sha256 becomes the digest")
	f.StringVar(&o.digest, "digest", "", "artifact digest, if it is already known (mutually exclusive with --artifact-file)")
	f.StringVar(&o.subjectType, "subject-type", "", "CycloneDX component type, e.g. application")
	f.StringVar(&o.subjectName, "subject-name", "", "subject name, e.g. ocidex")
	f.StringVar(&o.subjectGroup, "subject-group", "", "subject group, e.g. github.com/pfenerty")
	f.StringVar(&o.subjectPurl, "subject-purl", "", "subject package URL")
	f.StringVar(&o.version, "version", "", "subject version, e.g. v1.2.3")
	// Deliberately not defaulted to runtime.GOARCH: the machine running the
	// push is not necessarily the machine the artifact was built for, and a
	// wrong architecture is worse than an absent one.
	f.StringVar(&o.arch, "arch", "", "architecture the artifact was built for, e.g. amd64")
	// The --*-file variants exist for pipelines that split "work out the value"
	// from "do the push" across two containers. OCIDex's own sbom-push task is
	// the case in point: the step that derives the version from the git ref has
	// a shell, and the step that pushes is the published ocidex-cli image, which
	// is distroless and has none. A file on the shared workspace is the only
	// channel between them (ocidex-2u7y).
	f.StringVar(&o.versionFile, "version-file", "", "read --version from this file")
	f.StringVar(&o.archFile, "arch-file", "", "read --arch from this file")

	cmd.MarkFlagsMutuallyExclusive("artifact-file", "digest")
	cmd.MarkFlagsMutuallyExclusive("version", "version-file")
	cmd.MarkFlagsMutuallyExclusive("arch", "arch-file")

	return cmd
}

// resolveFileFlags folds --version-file and --arch-file into their literal
// counterparts. Cobra has already rejected passing both forms of either pair.
//
// A missing or blank file is an error rather than a silently omitted value: the
// caller asked for the value to come from that file, and a push that quietly
// records no version or no architecture is harder to notice than one that fails.
func (o *pushOpts) resolveFileFlags() error {
	for _, f := range []struct {
		flag string
		path string
		dst  *string
	}{
		{"--version-file", o.versionFile, &o.version},
		{"--arch-file", o.archFile, &o.arch},
	} {
		if f.path == "" {
			continue
		}
		data, err := os.ReadFile(f.path) //nolint:gosec // the path is the user's own argument
		if err != nil {
			return fmt.Errorf("reading %s: %w", f.flag, err)
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return fmt.Errorf("reading %s: %s is empty", f.flag, f.path)
		}
		*f.dst = value
	}
	return nil
}

func runSBOMPush(cmd *cobra.Command, cfg *rootConfig, o *pushOpts, sbomPath string) error {
	if err := validateSource(o.source); err != nil {
		return err
	}
	if err := o.resolveFileFlags(); err != nil {
		return err
	}

	api, err := cfg.authed()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(sbomPath) //nolint:gosec // the path is the user's own argument
	if err != nil {
		return fmt.Errorf("reading SBOM: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("reading SBOM: %s is empty", sbomPath)
	}

	digest := o.digest
	if o.artifactFile != "" {
		if digest, err = fileDigest(o.artifactFile); err != nil {
			return err
		}
	}

	out, err := api.IngestSBOM(cmd.Context(), data, client.IngestSbomParams{
		Source:       &o.source,
		Version:      optional(o.version),
		SubjectType:  optional(o.subjectType),
		SubjectName:  optional(o.subjectName),
		SubjectGroup: optional(o.subjectGroup),
		SubjectPurl:  optional(o.subjectPurl),
		Architecture: optional(o.arch),
		Digest:       optional(digest),
	})
	if err != nil {
		return fmt.Errorf("pushing SBOM: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s (%d components)\n", out.Id, out.ComponentCount)
	return nil
}

// sbomColumns is the table view of a SBOM: which build it describes and how
// big it is. Serial number and digest are filters rather than columns — they
// are too wide to read in a row and are in -o json when they are needed.
func sbomColumns() []output.Column[client.SBOMSummary] {
	return []output.Column[client.SBOMSummary]{
		{Header: "ID", Value: func(s client.SBOMSummary) string { return s.Id }},
		{Header: colVersion, Value: func(s client.SBOMSummary) string { return deref(s.SubjectVersion) }},
		{Header: "FLAVOR", Value: func(s client.SBOMSummary) string { return deref(s.Flavor) }},
		{Header: "ARCH", Value: func(s client.SBOMSummary) string { return deref(s.Architecture) }},
		{Header: "COMPONENTS", Value: func(s client.SBOMSummary) string { return derefInt(s.ComponentCount) }},
		{Header: "SUFFICIENT", Value: func(s client.SBOMSummary) string { return fmt.Sprint(s.Sufficient) }},
		{Header: colCreated, Value: func(s client.SBOMSummary) string { return s.CreatedAt.Format(time.RFC3339) }},
	}
}

func newSBOMListCmd(cfg *rootConfig) *cobra.Command {
	var filter client.SBOMFilter
	var limit, offset int32

	cmd := &cobra.Command{
		Use:   verbList,
		Short: "List visible SBOMs",
		Long: `List visible SBOMs.

--serial-number identifies one document; --digest identifies one subject, so it
returns every SBOM recorded for that image or artifact.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			page, err := cfg.api.ListSBOMs(cmd.Context(), filter, client.PageOpts{Limit: limit, Offset: offset})
			if err != nil {
				return fmt.Errorf("listing SBOMs: %w", err)
			}
			if err := output.List(cmd.OutOrStdout(), cfg.format, page.Data, sbomColumns()...); err != nil {
				return err
			}
			// Stderr, and only in table mode: -o json is for machines, which
			// already have the array and the pagination block.
			if cfg.format == output.Table && page.Pagination.HasMore {
				fmt.Fprintf(cmd.ErrOrStderr(), "\n%d shown; more available (use --offset %d)\n",
					len(page.Data), int(offset)+len(page.Data))
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&filter.SerialNumber, "serial-number", "", "return only the SBOM with this CycloneDX serial number")
	f.StringVar(&filter.Digest, "digest", "", "return only SBOMs whose subject has this digest")
	f.Int32Var(&limit, "limit", 0, "maximum SBOMs to return (server default 50)")
	f.Int32Var(&offset, "offset", 0, "index of the first SBOM to return")
	return cmd
}

func newSBOMGetCmd(cfg *rootConfig) *cobra.Command {
	var raw bool

	cmd := &cobra.Command{
		Use:   verbGet,
		Short: "Show one SBOM in full",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sbom, err := cfg.api.GetSBOM(cmd.Context(), args[0], raw)
			if err != nil {
				return fmt.Errorf("getting SBOM: %w", err)
			}
			if raw {
				// The stored document, byte-for-byte what OCIDex was given, so
				// it can be piped straight into another SBOM tool.
				if sbom.RawBom == nil {
					return fmt.Errorf("getting SBOM: %s has no stored raw document", args[0])
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(sbom.RawBom)
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, sbom)
		},
	}

	cmd.Flags().BoolVar(&raw, "raw", false, "print the stored CycloneDX document instead of OCIDex's summary")
	return cmd
}

func newSBOMDeleteCmd(cfg *rootConfig) *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a SBOM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if err := confirm(cmd, yes, fmt.Sprintf("Delete SBOM %s?", id)); err != nil {
				return err
			}
			if err := cfg.api.DeleteSBOM(cmd.Context(), id); err != nil {
				return fmt.Errorf("deleting SBOM: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", id)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "delete without confirming")
	return cmd
}

// derefInt renders an absent count as an empty cell rather than as 0, because
// "no SBOM component count recorded" and "zero components" are different facts.
func derefInt(n *int64) string {
	if n == nil {
		return ""
	}
	return strconv.FormatInt(*n, 10)
}

// validateSource rejects a bare source name before the request is made.
//
// Source names are unique per namespace, not globally, so the server has no way
// to resolve one on its own. Catching it here costs a round trip less than the
// 400 does and says which of the two forms is missing.
//
// This stands in for MarkFlagRequired so that a missing or malformed --source
// exits as a usage error rather than a generic failure.
func validateSource(source string) error {
	if source == "" {
		return usagef("--source is required: a UUID or <namespace>/<name>")
	}
	if _, err := uuid.Parse(source); err == nil {
		return nil
	}
	ns, name, ok := strings.Cut(source, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return usagef("--source must be a UUID or <namespace>/<name>")
	}
	return nil
}

// fileDigest returns the sha256 of the artifact file, prefixed the way the
// server records container digests so both kinds of subject read the same.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the user's own argument
	if err != nil {
		return "", fmt.Errorf("reading artifact: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing artifact: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// optional maps an unset flag to a nil query parameter, so the server sees the
// difference between "not supplied" and "supplied as empty".
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
