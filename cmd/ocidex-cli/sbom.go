package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/pkg/client"
)

func newSBOMCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Work with SBOMs",
	}
	cmd.AddCommand(newSBOMPushCmd(cfg))
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
}

func newSBOMPushCmd(cfg *rootConfig) *cobra.Command {
	o := &pushOpts{}

	cmd := &cobra.Command{
		Use:   "push <sbom-file>",
		Short: "Upload a CycloneDX SBOM",
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
    --version v1.2.3`,
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

	cmd.MarkFlagsMutuallyExclusive("artifact-file", "digest")

	return cmd
}

func runSBOMPush(cmd *cobra.Command, cfg *rootConfig, o *pushOpts, sbomPath string) error {
	if err := validateSource(o.source); err != nil {
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
		Digest:       optional(digest),
	})
	if err != nil {
		return fmt.Errorf("pushing SBOM: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s (%d components)\n", out.Id, out.ComponentCount)
	return nil
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
