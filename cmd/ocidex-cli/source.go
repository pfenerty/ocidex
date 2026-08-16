package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newSourceCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "source",
		Short: "Manage ingest sources",
		Long: `Manage ingest sources.

A source is one ingest channel into a namespace (ADR-039). ` + "`create`" + ` makes an
upload source, the kind SBOMs are pushed to directly; an OCI registry source is
created with ` + "`ocidex-cli registry create`" + `, which configures the registry behind
it at the same time.

Sources are named uniquely only within their namespace, so the API offers no
by-name lookup for them: these commands take a source UUID, which
` + "`ocidex-cli source list`" + ` prints.`,
	}
	cmd.AddCommand(
		newSourceListCmd(cfg),
		newSourceGetCmd(cfg),
		newSourceCreateCmd(cfg),
		newSourceUpdateCmd(cfg),
		newSourceDeleteCmd(cfg),
	)
	return cmd
}

// sourceColumns leads with the id because it is the only handle the other
// source commands accept.
func sourceColumns() []output.Column[client.SourceResponse] {
	return []output.Column[client.SourceResponse]{
		{Header: "ID", Value: func(s client.SourceResponse) string { return s.Id }},
		{Header: colName, Value: func(s client.SourceResponse) string { return s.Name }},
		{Header: "KIND", Value: func(s client.SourceResponse) string { return string(s.Kind) }},
		// namespace_name is documented as list-only; fall back to the id so the
		// column is never blank on a single-item view.
		{Header: "NAMESPACE", Value: func(s client.SourceResponse) string {
			if s.NamespaceName != nil && *s.NamespaceName != "" {
				return *s.NamespaceName
			}
			return s.NamespaceId
		}},
		{Header: colCreated, Value: func(s client.SourceResponse) string { return s.CreatedAt }},
	}
}

func newSourceListCmd(cfg *rootConfig) *cobra.Command {
	var namespace string

	cmd := &cobra.Command{
		Use:   verbList,
		Short: "List visible sources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			namespaceID := ""
			if namespace != "" {
				ns, err := getNamespace(cmd.Context(), cfg.api, namespace)
				if err != nil {
					return err
				}
				namespaceID = ns.Id
			}
			sources, err := cfg.api.ListSources(cmd.Context(), namespaceID)
			if err != nil {
				return fmt.Errorf("listing sources: %w", err)
			}
			return output.List(cmd.OutOrStdout(), cfg.format, sources, sourceColumns()...)
		},
	}

	cmd.Flags().StringVar(&namespace, "namespace", "", "only sources in this namespace, by id or name")
	return cmd
}

func newSourceGetCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   verbGet,
		Short: "Show one source in full",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := getSource(cmd.Context(), cfg.api, args[0])
			if err != nil {
				return err
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, src)
		},
	}
}

func newSourceCreateCmd(cfg *rootConfig) *cobra.Command {
	var name, namespace string

	cmd := &cobra.Command{
		Use:   verbCreate,
		Short: "Create an upload source in a namespace",
		Long: `Create an upload source in a namespace.

An upload source has nothing to configure: it is the channel SBOMs pushed with
` + "`ocidex-cli sbom push`" + ` are attributed to.

  ocidex-cli source create --name ci-uploads --namespace acme`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ns, err := getNamespace(cmd.Context(), cfg.api, namespace)
			if err != nil {
				return err
			}
			nsID, err := uuid.Parse(ns.Id)
			if err != nil {
				return fmt.Errorf("namespace %q has an unusable id %q: %w", ns.Name, ns.Id, err)
			}

			out, err := cfg.api.CreateSource(cmd.Context(), client.CreateSourceInputBody{
				Name:        name,
				NamespaceId: nsID,
			})
			if err != nil {
				return fmt.Errorf("creating source: %w", err)
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, out)
		},
	}

	f := cmd.Flags()
	f.StringVar(&name, "name", "", "source name, unique within the namespace")
	f.StringVar(&namespace, "namespace", "", "owning namespace, by id or name")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("namespace")
	return cmd
}

func newSourceUpdateCmd(cfg *rootConfig) *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Rename a source",
		Long: `Rename a source.

The name is all a source owns; its namespace and kind are fixed at creation, so
moving a source between namespaces means creating a new one.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := getSource(cmd.Context(), cfg.api, args[0])
			if err != nil {
				return err
			}
			updated, err := cfg.api.UpdateSource(cmd.Context(), src.Id, client.UpdateSourceInputBody{Name: name})
			if err != nil {
				return fmt.Errorf("updating source: %w", err)
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, updated)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "new source name")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newSourceDeleteCmd(cfg *rootConfig) *cobra.Command {
	return newDeleteCmd(
		verbDeleteID,
		"Delete a source and everything ingested through it",
		"source",
		func(ctx context.Context, ref string) (deletable, error) {
			src, err := getSource(ctx, cfg.api, ref)
			if err != nil {
				return deletable{}, err
			}
			return deletable{
				id:     src.Id,
				prompt: fmt.Sprintf("Delete source %s (%s) and everything ingested through it?", src.Name, src.Id),
			}, nil
		},
		func(ctx context.Context, id string) error { return cfg.api.DeleteSource(ctx, id) },
	)
}

// getSource fetches a source by id. Unlike registries and namespaces there is
// no by-name endpoint — source names are unique only within a namespace — so a
// non-UUID reference is rejected here rather than guessed at client-side.
func getSource(ctx context.Context, api client.Client, ref string) (client.SourceResponse, error) {
	if _, err := uuid.Parse(ref); err != nil {
		return client.SourceResponse{}, usagef(
			"%q is not a source id: source names are unique only within a namespace, so pass the id from `ocidex-cli source list`", ref)
	}
	src, err := api.GetSource(ctx, ref)
	if err != nil {
		return client.SourceResponse{}, fmt.Errorf("getting source %s: %w", ref, err)
	}
	return src, nil
}
