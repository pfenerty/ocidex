package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

// Agent keys (ADR-0058): what ocidex-mcp and other programs should run with
// instead of your personal login key.

var agentPresets = []string{"analyst", "remediation", "coverage"}

// agentKeySpec is what an agent key is made from.
type agentKeySpec struct {
	name       string
	label      string
	preset     string
	namespaces []string
	expiresIn  time.Duration
}

func (s *agentKeySpec) flags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&s.preset, "preset", "analyst", "what the agent may do: "+strings.Join(agentPresets, ", "))
	f.StringSliceVar(&s.namespaces, "namespace", nil,
		"namespace the agent may work in, by name or id, repeatable (default: your only namespace)")
	f.DurationVar(&s.expiresIn, "expires-in", 30*24*time.Hour, "stop the key working after this long; at most 2160h (90 days)")
	f.StringVar(&s.label, "label", "", "the client using the key, shown in the audit log and approvals (e.g. \"Claude Code on laptop\")")
}

// create mints the key and returns it. It never prints it.
func (s *agentKeySpec) create(ctx context.Context, api client.Client) (string, error) {
	if !slices.Contains(agentPresets, s.preset) {
		return "", usagef("--preset must be one of %s (got %q)", strings.Join(agentPresets, ", "), s.preset)
	}
	if s.expiresIn <= 0 || s.expiresIn > 90*24*time.Hour {
		return "", usagef("--expires-in must be between 1s and 2160h (got %s)", s.expiresIn)
	}
	nsIDs, err := resolveNamespaces(ctx, api, s.namespaces)
	if err != nil {
		return "", err
	}
	kind := client.CreateAPIKeyInputBodyKind("agent")
	preset := client.CreateAPIKeyInputBodyPreset(s.preset)
	at := time.Now().Add(s.expiresIn).UTC()
	body := client.CreateAPIKeyInputBody{Name: s.name, Kind: &kind, Preset: &preset, Namespaces: &nsIDs, ExpiresAt: &at}
	if s.label != "" {
		body.AgentLabel = &s.label
	}
	out, err := api.CreateAPIKey(ctx, body)
	if err != nil {
		return "", fmt.Errorf("creating agent key: %w", err)
	}
	return out.Key, nil
}

// resolveNamespaces turns names or ids into ids. With none given, a user in
// exactly one namespace gets that one; anyone else has to choose, since an
// agent key must be limited to named namespaces.
func resolveNamespaces(ctx context.Context, api client.Client, given []string) ([]string, error) {
	all, err := api.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	names := make([]string, len(all))
	for i, n := range all {
		names[i] = n.Name
	}
	if len(given) == 0 {
		if len(all) == 1 {
			return []string{all[0].Id}, nil
		}
		return nil, usagef("name the namespaces the agent may work in with --namespace (yours: %s)", strings.Join(names, ", "))
	}
	ids := make([]string, 0, len(given))
	for _, g := range given {
		i := slices.IndexFunc(all, func(n client.NamespaceResponse) bool { return n.Name == g || n.Id == g })
		if i < 0 {
			return nil, usagef("no namespace %q among yours (%s)", g, strings.Join(names, ", "))
		}
		ids = append(ids, all[i].Id)
	}
	return ids, nil
}

func newAgentCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Create keys for agents",
		Long: `Create keys for agents such as ocidex-mcp.

An agent key belongs to you but is limited to a preset, to named namespaces and
to an expiry, and the writes it may make can wait for your approval in the web
UI. To connect an MCP client in one step, use ` + "`ocidex-cli mcp install`" + `.`,
	}
	cmd.AddCommand(newAgentCreateCmd(cfg))
	return cmd
}

func newAgentCreateCmd(cfg *rootConfig) *cobra.Command {
	var spec agentKeySpec
	cmd := &cobra.Command{
		Use:   verbCreate,
		Short: "Create an agent key",
		Long: `Create an agent key.

Presets:
  analyst      reads everything in its namespaces, private data included; changes nothing
  remediation  as analyst, and may manage your watchlist
  coverage     as analyst, and may ask for scans; each scan waits for your approval

The key is printed once, on stdout, and never again.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := cfg.authed()
			if err != nil {
				return err
			}
			key, err := spec.create(cmd.Context(), api)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), key)
			fmt.Fprintln(cmd.ErrOrStderr(), "store this now — it cannot be shown again")
			return nil
		},
	}
	cmd.Flags().StringVar(&spec.name, "name", "", "human-readable label for the key (required)")
	_ = cmd.MarkFlagRequired("name")
	spec.flags(cmd)
	return cmd
}

func newApprovalCmd(cfg *rootConfig, openURL func(string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval",
		Short: "See agent requests waiting for approval",
		Long: `See agent requests waiting for approval.

Approving and denying happen only in the web UI, signed in: no key can approve,
or an agent holding one could approve itself. These commands list the requests
and take you to the page that decides them.`,
	}
	cmd.AddCommand(newApprovalListCmd(cfg), newApprovalOpenCmd(cfg, openURL))
	return cmd
}

func newApprovalListCmd(cfg *rootConfig) *cobra.Command {
	var status string
	cmd := &cobra.Command{
		Use:   verbList,
		Short: "List agent requests",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			api, err := cfg.authed()
			if err != nil {
				return err
			}
			items, err := api.ListApprovals(cmd.Context(), status)
			if err != nil {
				return fmt.Errorf("listing approvals: %w", err)
			}
			return output.List(cmd.OutOrStdout(), cfg.format, items,
				output.Column[client.PendingActionView]{Header: "ID", Value: func(a client.PendingActionView) string { return a.Id.String() }},
				output.Column[client.PendingActionView]{Header: "STATUS", Value: func(a client.PendingActionView) string { return string(a.Status) }},
				output.Column[client.PendingActionView]{Header: "AGENT", Value: func(a client.PendingActionView) string {
					if a.AgentLabel == nil {
						return ""
					}
					return *a.AgentLabel
				}},
				output.Column[client.PendingActionView]{Header: "EFFECT", Value: func(a client.PendingActionView) string { return a.Effect }},
				output.Column[client.PendingActionView]{Header: colCreated, Value: func(a client.PendingActionView) string { return a.CreatedAt.Format(time.RFC3339) }},
			)
		},
	}
	cmd.Flags().StringVar(&status, "status", "pending", "only requests in this status: pending, approved, denied, expired, executed, failed (empty for all)")
	return cmd
}

func newApprovalOpenCmd(cfg *rootConfig, openURL func(string) error) *cobra.Command {
	return &cobra.Command{
		Use:   "open <id>",
		Short: "Open a request's approval page in the browser",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			u := strings.TrimRight(cfg.server, "/") + "/approvals/" + args[0]
			fmt.Fprintln(cmd.OutOrStdout(), u)
			if err := openURL(u); err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "could not open a browser; open the URL above")
			}
			return nil
		},
	}
}
