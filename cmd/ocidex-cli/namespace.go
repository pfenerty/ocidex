package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newNamespaceCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: "Manage namespaces",
		Long: `Manage namespaces.

A namespace owns sources and everything ingested through them, and its
visibility governs who can read those artifacts (ADR-039).

Every command that takes a namespace accepts either its UUID or its name; a
name is resolved through /api/v1/namespaces/by-name before the call.`,
	}
	cmd.AddCommand(
		newNamespaceListCmd(cfg),
		newNamespaceGetCmd(cfg),
		newNamespaceCreateCmd(cfg),
		newNamespaceUpdateCmd(cfg),
		newNamespaceDeleteCmd(cfg),
	)
	return cmd
}

// namespaceColumns is the view of a namespace: what it is called, who can see
// it, and who owns it. Everything else is in -o json.
func namespaceColumns() []output.Column[client.NamespaceResponse] {
	return []output.Column[client.NamespaceResponse]{
		{Header: colName, Value: func(n client.NamespaceResponse) string { return n.Name }},
		{Header: "VISIBILITY", Value: func(n client.NamespaceResponse) string { return string(n.Visibility) }},
		{Header: "OWNER", Value: func(n client.NamespaceResponse) string { return deref(n.OwnerUsername) }},
		{Header: colCreated, Value: func(n client.NamespaceResponse) string { return n.CreatedAt }},
	}
}

// The namespace list endpoint returns every namespace the caller can see, with
// no pagination, so there is nothing here for --limit/--offset to do.
func newNamespaceListCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   verbList,
		Short: "List visible namespaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			namespaces, err := cfg.api.ListNamespaces(cmd.Context())
			if err != nil {
				return fmt.Errorf("listing namespaces: %w", err)
			}
			return output.List(cmd.OutOrStdout(), cfg.format, namespaces, namespaceColumns()...)
		},
	}
}

func newNamespaceGetCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id|name>",
		Short: "Show one namespace in full",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ns, err := getNamespace(cmd.Context(), cfg.api, args[0])
			if err != nil {
				return err
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, ns)
		},
	}
}

func newNamespaceCreateCmd(cfg *rootConfig) *cobra.Command {
	var name, visibility string

	cmd := &cobra.Command{
		Use:   verbCreate,
		Short: "Create a namespace",
		Long: `Create a namespace.

Visibility defaults to private, so a namespace created without --visibility is
readable only by its owner.

  ocidex-cli namespace create --name acme --visibility public`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := cfg.api.CreateNamespace(cmd.Context(), client.CreateNamespaceInputBody{
				Name:       name,
				Visibility: optionalEnum[client.CreateNamespaceInputBodyVisibility](visibility),
			})
			if err != nil {
				return fmt.Errorf("creating namespace: %w", err)
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, out)
		},
	}

	f := cmd.Flags()
	f.StringVar(&name, "name", "", "namespace name, unique across the server")
	f.StringVar(&visibility, "visibility", "", "who can read artifacts under it: public or private (default private)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newNamespaceUpdateCmd(cfg *rootConfig) *cobra.Command {
	var name, visibility string

	cmd := &cobra.Command{
		Use:   "update <id|name>",
		Short: "Rename a namespace or change its visibility",
		Long: `Rename a namespace or change its visibility.

Both fields are omit-to-keep on the API's PATCH, so only the flags actually
given are sent — no read-modify-write, and nothing else can be reset by
accident.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			current, err := getNamespace(cmd.Context(), cfg.api, args[0])
			if err != nil {
				return err
			}

			var body client.UpdateNamespaceInputBody
			if cmd.Flags().Changed("name") {
				body.Name = &name
			}
			if cmd.Flags().Changed("visibility") {
				body.Visibility = optionalEnum[client.UpdateNamespaceInputBodyVisibility](visibility)
			}
			if body.Name == nil && body.Visibility == nil {
				return usagef("nothing to update: pass --name or --visibility")
			}

			updated, err := cfg.api.UpdateNamespace(cmd.Context(), current.Id, body)
			if err != nil {
				return fmt.Errorf("updating namespace: %w", err)
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, updated)
		},
	}

	f := cmd.Flags()
	f.StringVar(&name, "name", "", "new namespace name")
	f.StringVar(&visibility, "visibility", "", "new visibility: public or private")
	return cmd
}

func newNamespaceDeleteCmd(cfg *rootConfig) *cobra.Command {
	return newDeleteCmd(
		"delete <id|name>",
		"Delete a namespace and everything ingested under it",
		"namespace",
		func(ctx context.Context, ref string) (deletable, error) {
			ns, err := getNamespace(ctx, cfg.api, ref)
			if err != nil {
				return deletable{}, err
			}
			// The prompt names the blast radius rather than the namespace
			// alone: this takes its sources and their artifacts with it.
			return deletable{
				id: ns.Id,
				prompt: fmt.Sprintf(
					"Delete namespace %s (%s), its sources, and everything ingested under them?", ns.Name, ns.Id),
			}, nil
		},
		func(ctx context.Context, id string) error { return cfg.api.DeleteNamespace(ctx, id) },
	)
}

// getNamespace resolves either form of namespace reference. A name is resolved
// server-side, so the CLI agrees with the server about which namespace a name
// means instead of listing and filtering itself.
func getNamespace(ctx context.Context, api client.Client, ref string) (client.NamespaceResponse, error) {
	if ref == "" {
		return client.NamespaceResponse{}, usagef("namespace id or name is required")
	}
	if _, err := uuid.Parse(ref); err == nil {
		ns, err := api.GetNamespace(ctx, ref)
		if err != nil {
			return client.NamespaceResponse{}, fmt.Errorf("getting namespace %s: %w", ref, err)
		}
		return ns, nil
	}
	ns, err := api.GetNamespaceByName(ctx, ref)
	if err != nil {
		return client.NamespaceResponse{}, fmt.Errorf("getting namespace %q: %w", ref, err)
	}
	return ns, nil
}
