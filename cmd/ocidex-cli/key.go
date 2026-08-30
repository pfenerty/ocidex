package main

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

// keyCapabilities is the server's vocabulary, repeated here so a typo is
// rejected before it becomes a key with the wrong power.
var keyCapabilities = []string{
	"read_private",
	"ingest",
	"trigger_scan",
	"push_inventory",
	"delete_artifact",
	"manage_source",
	"manage_cluster",
	"read_secret",
	"manage_member",
	"delete_namespace",
}

func newKeyCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage your API keys",
		Long: `Manage your API keys.

Every subcommand here needs an existing key, so the first one has to come from
the web UI. After that a key can mint its successors.`,
	}
	cmd.AddCommand(newKeyListCmd(cfg), newKeyCreateCmd(cfg), newKeyDeleteCmd(cfg))
	return cmd
}

func keyColumns() []output.Column[client.KeyMetaResponse] {
	return []output.Column[client.KeyMetaResponse]{
		{Header: "ID", Value: func(k client.KeyMetaResponse) string { return k.Id }},
		{Header: colName, Value: func(k client.KeyMetaResponse) string { return k.Name }},
		{Header: "PREFIX", Value: func(k client.KeyMetaResponse) string { return k.Prefix }},
		{Header: "CAPABILITIES", Value: func(k client.KeyMetaResponse) string {
			// A key holding everything is the common case and its ten names
			// would swamp the row, so it collapses to one word.
			var caps []string
			if k.Capabilities != nil {
				caps = *k.Capabilities
			}
			if len(caps) == len(keyCapabilities) {
				return "all"
			}
			if len(caps) == 0 {
				return "none"
			}
			return strings.Join(caps, ",")
		}},
		{Header: "LAST USED", Value: func(k client.KeyMetaResponse) string {
			// Never-used is the interesting state — a key issued and forgotten
			// is one to revoke — so it gets a word, not an empty cell.
			if k.LastUsedAt == nil {
				return "never"
			}
			return k.LastUsedAt.Format(time.RFC3339)
		}},
		{Header: colCreated, Value: func(k client.KeyMetaResponse) string { return k.CreatedAt.Format(time.RFC3339) }},
	}
}

func newKeyListCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   verbList,
		Short: "List your API keys",
		Long: `List your API keys.

Only metadata: the key itself is stored hashed and cannot be shown again. PREFIX
is what identifies a key in the audit log.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := cfg.authed()
			if err != nil {
				return err
			}
			keys, err := api.ListAPIKeys(cmd.Context())
			if err != nil {
				return fmt.Errorf("listing keys: %w", err)
			}
			return output.List(cmd.OutOrStdout(), cfg.format, keys, keyColumns()...)
		},
	}
}

func newKeyCreateCmd(cfg *rootConfig) *cobra.Command {
	var name string
	var caps []string

	cmd := &cobra.Command{
		Use:   verbCreate,
		Short: "Create an API key",
		Long: `Create an API key.

The key is printed once, on stdout, and never again. Everything else this
command says goes to stderr, so ` + "`ocidex-cli key create --name ci > key.txt`" + `
captures exactly the key and nothing else.

Capabilities are a ceiling, not a grant: the key can never do more than your
namespace roles allow, and a role change narrows every key you hold without any
key change. Omitting --capability asks for all of them, which resolves to
exactly what you can do. Name them where something narrower will do: a key that
only ingests cannot delete an SBOM even where you can.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateKeyCapabilities(caps); err != nil {
				return err
			}
			api, err := cfg.authed()
			if err != nil {
				return err
			}

			body := client.CreateAPIKeyInputBody{Name: name}
			if len(caps) > 0 {
				typed := make([]client.CreateAPIKeyInputBodyCapabilities, len(caps))
				for i, c := range caps {
					typed[i] = client.CreateAPIKeyInputBodyCapabilities(c)
				}
				body.Capabilities = &typed
			}
			out, err := api.CreateAPIKey(cmd.Context(), body)
			if err != nil {
				return fmt.Errorf("creating key: %w", err)
			}

			if cfg.format != output.Table {
				return output.Item(cmd.OutOrStdout(), cfg.format, out)
			}
			fmt.Fprintln(cmd.OutOrStdout(), out.Key)
			fmt.Fprintln(cmd.ErrOrStderr(), "store this now — it cannot be shown again")
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&name, "name", "", "human-readable label for the key (required)")
	f.StringSliceVar(&caps, "capability", nil,
		"capability this key may exercise, repeatable (default: all of them)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

// validateKeyCapabilities rejects an unknown capability before sending it, so a
// typo fails loudly here rather than quietly yielding a key that is missing the
// power it was created for.
func validateKeyCapabilities(caps []string) error {
	for _, c := range caps {
		if !slices.Contains(keyCapabilities, c) {
			return usagef("--capability must be one of %s (got %q)",
				strings.Join(keyCapabilities, ", "), c)
		}
	}
	return nil
}

func newKeyDeleteCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   verbDeleteID,
		Short: "Revoke an API key",
		Long: `Revoke an API key.

Takes the key's UUID, which ` + "`key list`" + ` shows — not the key itself, which
you are not expected to still have.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := cfg.authed()
			if err != nil {
				return err
			}
			if err := api.DeleteAPIKey(cmd.Context(), args[0]); err != nil {
				return fmt.Errorf("deleting key: %w", err)
			}
			if cfg.format == output.Table {
				fmt.Fprintf(cmd.ErrOrStderr(), "key %s revoked\n", args[0])
			}
			return nil
		},
	}
}
