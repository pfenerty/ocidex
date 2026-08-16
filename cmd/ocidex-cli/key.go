package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

// keyScopes is the server's vocabulary, repeated here so a typo is rejected
// before it becomes a key with the wrong power.
var keyScopes = []string{"read", "read-write"}

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
		{Header: "SCOPE", Value: func(k client.KeyMetaResponse) string { return string(k.Scope) }},
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
	var name, scope string

	cmd := &cobra.Command{
		Use:   verbCreate,
		Short: "Create an API key",
		Long: `Create an API key.

The key is printed once, on stdout, and never again. Everything else this
command says goes to stderr, so ` + "`ocidex-cli key create --name ci > key.txt`" + `
captures exactly the key and nothing else.

Scope defaults to read. Ask for read-write only where something actually
writes: a leaked read key cannot delete an SBOM.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateKeyScope(scope); err != nil {
				return err
			}
			api, err := cfg.authed()
			if err != nil {
				return err
			}

			body := client.CreateAPIKeyInputBody{Name: name}
			if scope != "" {
				s := client.CreateAPIKeyInputBodyScope(scope)
				body.Scope = &s
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
	f.StringVar(&scope, "scope", "", "read or read-write (server default read)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

// validateKeyScope rejects an unknown scope before sending it, so a typo fails
// loudly here rather than silently yielding whatever the server defaults to.
func validateKeyScope(scope string) error {
	if scope == "" {
		return nil
	}
	for _, s := range keyScopes {
		if scope == s {
			return nil
		}
	}
	return usagef("--scope must be read or read-write (got %q)", scope)
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
