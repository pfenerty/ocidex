package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newRegistryCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Manage OCI registry sources",
		Long: `Manage OCI registry sources.

Every command that takes a registry accepts either its UUID or its name; a name
is resolved through /api/v1/registries/by-name before the call.`,
	}
	cmd.AddCommand(
		newRegistryListCmd(cfg),
		newRegistryGetCmd(cfg),
		newRegistryCreateCmd(cfg),
		newRegistryUpdateCmd(cfg),
		newRegistryDeleteCmd(cfg),
		newRegistryScanCmd(cfg),
	)
	return cmd
}

// registryColumns is the table view of a registry: what it is, where it points,
// and whether OCIDex is actually polling it. Everything else is in -o json.
func registryColumns() []output.Column[client.RegistryResponse] {
	return []output.Column[client.RegistryResponse]{
		{Header: colName, Value: func(r client.RegistryResponse) string { return r.Name }},
		{Header: "URL", Value: func(r client.RegistryResponse) string { return r.Url }},
		{Header: colType, Value: func(r client.RegistryResponse) string { return r.Type }},
		{Header: "SCAN MODE", Value: func(r client.RegistryResponse) string { return r.ScanMode }},
		{Header: "ENABLED", Value: func(r client.RegistryResponse) string { return fmt.Sprint(r.Enabled) }},
		{Header: "VISIBILITY", Value: func(r client.RegistryResponse) string { return r.Visibility }},
		{Header: "LAST POLLED", Value: func(r client.RegistryResponse) string { return deref(r.LastPolledAt) }},
	}
}

func newRegistryListCmd(cfg *rootConfig) *cobra.Command {
	var limit, offset int32

	cmd := &cobra.Command{
		Use:   verbList,
		Short: "List visible registries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			page, err := cfg.api.ListRegistries(cmd.Context(), client.PageOpts{Limit: limit, Offset: offset})
			if err != nil {
				return fmt.Errorf("listing registries: %w", err)
			}
			if err := output.List(cmd.OutOrStdout(), cfg.format, page.Data, registryColumns()...); err != nil {
				return err
			}
			// The count goes to stderr so it never lands in a piped table, and
			// only in table mode: -o json is for machines, which have the array.
			if cfg.format == output.Table {
				fmt.Fprintf(cmd.ErrOrStderr(), "\n%d of %d\n", len(page.Data), page.Pagination.Total)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.Int32Var(&limit, "limit", 0, "maximum registries to return (server default 50)")
	f.Int32Var(&offset, "offset", 0, "index of the first registry to return")
	return cmd
}

func newRegistryGetCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id|name>",
		Short: "Show one registry in full",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := getRegistry(cmd.Context(), cfg.api, args[0])
			if err != nil {
				return err
			}
			return output.Item(cmd.OutOrStdout(), cfg.format, reg)
		},
	}
}

// registryOpts carries the flags shared by create and update. Fields the API
// documents as controller-owned (managed_by, managed_ref) have no flag: they
// belong to whatever system reconciles the registry, not to a person.
type registryOpts struct {
	name               string
	url                string
	typ                string
	namespace          string
	visibility         string
	scanMode           string
	pollInterval       int64
	insecure           bool
	enabled            bool
	includeUntagged    bool
	repositories       []string
	repositoryPatterns []string
	tagPatterns        []string
	authUsername       string
	authTokenFile      string
	webhookSecretFile  string
	verificationMode   string
	trustIdentity      string
	trustIssuer        string
	trustPublicKeyFile string
}

// bindCommon registers the flags create and update share. The two secrets are
// read from files rather than taken as values: a registry PAT in argv is
// visible in the process table and in any shell history or CI log.
func (o *registryOpts) bindCommon(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.url, "url", "", "registry address, e.g. ghcr.io")
	f.StringVar(&o.typ, "type", "", "registry type, e.g. ghcr, zot, harbor, docker")
	f.StringVar(&o.visibility, "visibility", "", "public or private")
	f.StringVar(&o.scanMode, "scan-mode", "", "scanning mode")
	f.Int64Var(&o.pollInterval, "poll-interval-minutes", 0, "minutes between polls")
	f.BoolVar(&o.insecure, "insecure", false, "allow HTTP (non-TLS) connections")
	f.BoolVar(&o.includeUntagged, "include-untagged", false, "scan untagged manifests (zot, harbor, ghcr)")
	f.StringSliceVar(&o.repositories, "repository", nil, "explicit repository to walk; repeatable, bypasses catalog discovery")
	f.StringSliceVar(&o.repositoryPatterns, "repository-pattern", nil, "glob for repositories to ingest; repeatable, empty = all")
	f.StringSliceVar(&o.tagPatterns, "tag-pattern", nil, "glob or 'semver' for tags to ingest; repeatable, empty = all")
	f.StringVar(&o.authUsername, "auth-username", "", "registry username; omit for anonymous access")
	f.StringVar(&o.authTokenFile, "auth-token-file", "", "file holding the registry token or PAT")
	f.StringVar(&o.verificationMode, "verification-mode", "", "signature verification: none, public_key, or keyless")
	f.StringVar(&o.trustIdentity, "trust-identity", "", "regex matched against the Fulcio certificate SAN (keyless)")
	f.StringVar(&o.trustIssuer, "trust-issuer", "", "expected OIDC issuer URL (keyless)")
	f.StringVar(&o.trustPublicKeyFile, "trust-public-key-file", "", "file holding the PEM-encoded EC public key (public_key)")
}

// secrets reads the file-backed flags, so a create or update fails before it
// reaches the server if a path is wrong.
func (o *registryOpts) secrets() (authToken, webhookSecret, trustPublicKey string, err error) {
	for _, s := range []struct {
		path string
		into *string
	}{
		{o.authTokenFile, &authToken},
		{o.webhookSecretFile, &webhookSecret},
		{o.trustPublicKeyFile, &trustPublicKey},
	} {
		if s.path == "" {
			continue
		}
		data, readErr := os.ReadFile(s.path) //nolint:gosec // the path is the user's own argument
		if readErr != nil {
			return "", "", "", fmt.Errorf("reading %s: %w", s.path, readErr)
		}
		*s.into = strings.TrimSpace(string(data))
	}
	return authToken, webhookSecret, trustPublicKey, nil
}

func newRegistryCreateCmd(cfg *rootConfig) *cobra.Command {
	o := &registryOpts{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register an OCI registry to scan",
		Long: `Register an OCI registry to scan.

Omitting --namespace gives the registry a namespace of its own, named after it.
Pass an existing namespace to put several sources under one owner and one
visibility setting.`,
		Example: `  ocidex-cli registry create --name ghcr --url ghcr.io --type ghcr \
    --namespace myorg --tag-pattern semver --auth-token-file ./ghcr.pat`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRegistryCreate(cmd, cfg, o)
		},
	}

	o.bindCommon(cmd)
	f := cmd.Flags()
	f.StringVar(&o.name, "name", "", "human-readable registry name (required)")
	f.StringVar(&o.namespace, "namespace", "", "namespace to create the registry in, created on first use")
	// Create only: the PATCH body has no webhook secret. An existing one is
	// rotated through the webhook-secret endpoint, not overwritten by hand.
	f.StringVar(&o.webhookSecretFile, "webhook-secret-file", "", "file holding the bearer token required on incoming webhooks")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("type")

	return cmd
}

func runRegistryCreate(cmd *cobra.Command, cfg *rootConfig, o *registryOpts) error {
	authToken, webhookSecret, trustPublicKey, err := o.secrets()
	if err != nil {
		return err
	}

	body := client.CreateRegistryInputBody{
		Name:               o.name,
		Url:                o.url,
		Type:               client.CreateRegistryInputBodyType(o.typ),
		Insecure:           o.insecure,
		Namespace:          optional(o.namespace),
		Visibility:         optionalEnum[client.CreateRegistryInputBodyVisibility](o.visibility),
		ScanMode:           optionalEnum[client.CreateRegistryInputBodyScanMode](o.scanMode),
		VerificationMode:   optionalEnum[client.CreateRegistryInputBodyVerificationMode](o.verificationMode),
		Repositories:       optionalSlice(o.repositories),
		RepositoryPatterns: optionalSlice(o.repositoryPatterns),
		TagPatterns:        optionalSlice(o.tagPatterns),
		AuthUsername:       optional(o.authUsername),
		AuthToken:          optional(authToken),
		WebhookSecret:      optional(webhookSecret),
		TrustIdentity:      optional(o.trustIdentity),
		TrustIssuer:        optional(o.trustIssuer),
		TrustPublicKey:     optional(trustPublicKey),
	}
	if cmd.Flags().Changed("poll-interval-minutes") {
		body.PollIntervalMinutes = &o.pollInterval
	}
	if cmd.Flags().Changed("include-untagged") {
		body.IncludeUntagged = &o.includeUntagged
	}

	out, err := cfg.api.CreateRegistry(cmd.Context(), body)
	if err != nil {
		return fmt.Errorf("creating registry: %w", err)
	}
	return output.Item(cmd.OutOrStdout(), cfg.format, out)
}

func newRegistryUpdateCmd(cfg *rootConfig) *cobra.Command {
	o := &registryOpts{}

	cmd := &cobra.Command{
		Use:   "update <id|name>",
		Short: "Change a registry's configuration",
		Long: `Change a registry's configuration.

Only the flags you pass are changed: the current registry is read first and the
given flags applied to it, because the API's PATCH body is a whole registry.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryUpdate(cmd, cfg, o, args[0])
		},
	}

	o.bindCommon(cmd)
	f := cmd.Flags()
	f.StringVar(&o.name, "name", "", "rename the registry")
	f.BoolVar(&o.enabled, "enabled", true, "whether OCIDex polls this registry")
	return cmd
}

func runRegistryUpdate(cmd *cobra.Command, cfg *rootConfig, o *registryOpts, ref string) error {
	authToken, _, trustPublicKey, err := o.secrets()
	if err != nil {
		return err
	}

	current, err := getRegistry(cmd.Context(), cfg.api, ref)
	if err != nil {
		return err
	}

	body := updateBodyFrom(current)
	applyChanged(cmd, map[string]func(){
		"name":                  func() { body.Name = o.name },
		"url":                   func() { body.Url = o.url },
		"type":                  func() { body.Type = client.UpdateRegistryInputBodyType(o.typ) },
		"enabled":               func() { body.Enabled = o.enabled },
		"insecure":              func() { body.Insecure = o.insecure },
		"include-untagged":      func() { body.IncludeUntagged = &o.includeUntagged },
		"poll-interval-minutes": func() { body.PollIntervalMinutes = &o.pollInterval },
		"visibility":            func() { body.Visibility = optionalEnum[client.UpdateRegistryInputBodyVisibility](o.visibility) },
		"scan-mode":             func() { body.ScanMode = optionalEnum[client.UpdateRegistryInputBodyScanMode](o.scanMode) },
		"verification-mode": func() {
			body.VerificationMode = optionalEnum[client.UpdateRegistryInputBodyVerificationMode](o.verificationMode)
		},
		"repository":            func() { body.Repositories = &o.repositories },
		"repository-pattern":    func() { body.RepositoryPatterns = &o.repositoryPatterns },
		"tag-pattern":           func() { body.TagPatterns = &o.tagPatterns },
		"auth-username":         func() { body.AuthUsername = &o.authUsername },
		"auth-token-file":       func() { body.AuthToken = &authToken },
		"trust-identity":        func() { body.TrustIdentity = &o.trustIdentity },
		"trust-issuer":          func() { body.TrustIssuer = &o.trustIssuer },
		"trust-public-key-file": func() { body.TrustPublicKey = &trustPublicKey },
	})

	updated, err := cfg.api.UpdateRegistry(cmd.Context(), current.Id, body)
	if err != nil {
		return fmt.Errorf("updating registry: %w", err)
	}
	return output.Item(cmd.OutOrStdout(), cfg.format, updated)
}

// updateBodyFrom is the read half of the read-modify-write: everything the
// server would otherwise reset is carried over from the current registry.
//
// The two credentials are deliberately not carried over — the API never returns
// them (only has_auth and has_secret), so there is nothing to carry.
func updateBodyFrom(r client.RegistryResponse) client.UpdateRegistryInputBody {
	body := client.UpdateRegistryInputBody{
		Name:                r.Name,
		Url:                 r.Url,
		Type:                client.UpdateRegistryInputBodyType(r.Type),
		Enabled:             r.Enabled,
		Insecure:            r.Insecure,
		IncludeUntagged:     &r.IncludeUntagged,
		PollIntervalMinutes: &r.PollIntervalMinutes,
		Repositories:        r.Repositories,
		RepositoryPatterns:  r.RepositoryPatterns,
		TagPatterns:         r.TagPatterns,
		TrustIdentity:       r.TrustIdentity,
		TrustIssuer:         r.TrustIssuer,
		TrustPublicKey:      r.TrustPublicKey,
	}
	body.ScanMode = optionalEnum[client.UpdateRegistryInputBodyScanMode](r.ScanMode)
	body.Visibility = optionalEnum[client.UpdateRegistryInputBodyVisibility](r.Visibility)
	body.VerificationMode = optionalEnum[client.UpdateRegistryInputBodyVerificationMode](string(r.VerificationMode))
	return body
}

// applyChanged runs the mutation for every flag the user actually gave, so an
// unset flag's zero value never overwrites the registry's current setting.
func applyChanged(cmd *cobra.Command, appliers map[string]func()) {
	for name, apply := range appliers {
		if cmd.Flags().Changed(name) {
			apply()
		}
	}
}

func newRegistryDeleteCmd(cfg *rootConfig) *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "delete <id|name>",
		Short: "Delete a registry and everything ingested from it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := getRegistry(cmd.Context(), cfg.api, args[0])
			if err != nil {
				return err
			}
			if err := confirm(cmd, yes, fmt.Sprintf("Delete registry %s (%s)?", reg.Name, reg.Id)); err != nil {
				return err
			}
			if err := cfg.api.DeleteRegistry(cmd.Context(), reg.Id); err != nil {
				return fmt.Errorf("deleting registry: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", reg.Id)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not prompt for confirmation")
	return cmd
}

func newRegistryScanCmd(cfg *rootConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "scan <id|name>",
		Short: "Trigger an ad-hoc scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := getRegistry(cmd.Context(), cfg.api, args[0])
			if err != nil {
				return err
			}
			out, err := cfg.api.ScanRegistry(cmd.Context(), reg.Id)
			if err != nil {
				return fmt.Errorf("scanning registry: %w", err)
			}
			// The endpoint answers with a confirmation, not a job id; the jobs
			// it enqueues are visible through `ocidex-cli job list`.
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", reg.Id, out.Message)
			return nil
		},
	}
}

// getRegistry resolves either form of registry reference. A name is resolved
// server-side rather than by listing and filtering, so the answer is the same
// one the server would give a webhook.
func getRegistry(ctx context.Context, api client.Client, ref string) (client.RegistryResponse, error) {
	if ref == "" {
		return client.RegistryResponse{}, usagef("registry id or name is required")
	}
	if _, err := uuid.Parse(ref); err == nil {
		reg, err := api.GetRegistry(ctx, ref)
		if err != nil {
			return client.RegistryResponse{}, fmt.Errorf("getting registry %s: %w", ref, err)
		}
		return reg, nil
	}
	reg, err := api.GetRegistryByName(ctx, ref)
	if err != nil {
		return client.RegistryResponse{}, fmt.Errorf("getting registry %q: %w", ref, err)
	}
	return reg, nil
}

// confirm asks before a destructive action. Without a terminal to ask on it
// refuses rather than assuming yes, so a script that forgot --yes fails loudly
// instead of deleting a registry.
func confirm(cmd *cobra.Command, yes bool, prompt string) error {
	if yes {
		return nil
	}
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok {
		info, err := f.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return usagef("%s not a terminal: pass --yes to confirm", prompt)
		}
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
		return fmt.Errorf("cancelled")
	}
	return nil
}

// deref renders an absent optional string as an empty cell.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// optionalEnum maps an unset flag to a nil field. The value is passed through
// unchecked: the server owns the list of valid values, and duplicating it here
// would only mean the CLI rejects a value a newer server accepts.
func optionalEnum[T ~string](s string) *T {
	if s == "" {
		return nil
	}
	v := T(s)
	return &v
}

// optionalSlice distinguishes "flag not given" from "given as empty", which the
// API reads as "no filter" rather than "leave unchanged".
func optionalSlice(v []string) *[]string {
	if len(v) == 0 {
		return nil
	}
	return &v
}
