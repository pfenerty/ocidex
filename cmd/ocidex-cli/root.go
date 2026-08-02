package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

// defaultServer is the last resort when no flag, environment variable, or
// config file names a server.
const defaultServer = "http://localhost:8080"

// Vocabulary shared across the command files: the same verb and the same table
// headers appear in every noun, and they should stay spelled the same way.
const (
	verbList = "list"
	verbGet  = "get <id>"

	colName    = "NAME"
	colType    = "TYPE"
	colVersion = "VERSION"
	colSBOM    = "SBOM"
	colVulns   = "VULNS"
	colCreated = "CREATED"
)

// usageError marks a failure the user can fix by re-reading the usage text, as
// opposed to one the server or the filesystem caused. main maps it to exit
// code 2 and prints usage alongside the message.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usagef(format string, a ...any) error {
	return &usageError{err: fmt.Errorf(format, a...)}
}

// rootConfig is the resolved configuration every subcommand shares, plus the
// client built from it. It is populated once, in the root command's
// PersistentPreRunE, so no subcommand repeats the precedence rules.
type rootConfig struct {
	server string
	apiKey string
	format output.Format

	// api is the interface, never the concrete implementation, so command
	// tests can substitute client.FakeClient.
	api client.Client

	// newClient builds api once the server URL and key are known. It is a field
	// so tests can hand back a client.FakeClient without standing up a server.
	newClient func(client.Config) client.Client

	// resolved records that PersistentPreRunE ran to completion. Cobra reports
	// flag-parsing, required-flag, and unknown-command failures the same way it
	// reports a command's own error, and this is the difference: anything that
	// fails before resolution is a usage problem.
	resolved bool

	// Flag-bound values. They are read through cmd.Flags().Changed rather than
	// directly, so an unset flag falls through to the environment and the
	// config file instead of overriding them with "".
	serverFlag string
	outputFlag string
}

func newRootCmd() (*cobra.Command, *rootConfig) {
	cfg := &rootConfig{
		newClient: func(c client.Config) client.Client { return client.New(c) },
	}

	cmd := &cobra.Command{
		Use:   "ocidex-cli",
		Short: "Command-line client for OCIDex",
		Long: `Command-line client for OCIDex.

Commands are noun then verb: ` + "`ocidex-cli sbom push`" + `, ` + "`ocidex-cli registry list`" + `.

Configuration is resolved in this order, most specific first: command-line flag,
environment variable, ~/.config/ocidex/config.yaml, built-in default. The API key
is deliberately not a flag — see docs/adr/0029-cli-design.md.`,
		// Errors returned by RunE are reported by main; cobra printing them a
		// second time, with usage attached, buries the actual message.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			return cfg.resolve(c)
		},
	}

	f := cmd.PersistentFlags()
	f.StringVar(&cfg.serverFlag, "server", "",
		"OCIDex base URL (env OCIDEX_URL, config server, default "+defaultServer+")")
	f.StringVarP(&cfg.outputFlag, "output", "o", "",
		"output format: table, json, or yaml (config output, default table)")

	cmd.AddCommand(newSBOMCmd(cfg), newRegistryCmd(cfg), newArtifactCmd(cfg),
		newComponentCmd(cfg), newJobCmd(cfg), newKeyCmd(cfg),
		newLoginCmd(cfg), newLogoutCmd())
	return cmd, cfg
}

// resolve applies the precedence rules and constructs the client.
func (c *rootConfig) resolve(cmd *cobra.Command) error {
	// Set before the first fallible step: a failure from here on is a real
	// problem with the configuration, not a malformed command line.
	c.resolved = true

	file, err := loadConfigFile()
	if err != nil {
		return err
	}

	c.server = firstNonEmpty(
		flagValue(cmd, "server", c.serverFlag),
		os.Getenv("OCIDEX_URL"),
		file.Server,
		defaultServer,
	)

	// Env before file, and no flag at all: a key in argv is visible in the
	// process table and echoed by any CI runner that logs its commands.
	c.apiKey = firstNonEmpty(os.Getenv("OCIDEX_API_KEY"), file.APIKey)

	format := output.Format(firstNonEmpty(flagValue(cmd, "output", c.outputFlag), file.Output, string(output.Table)))
	if !output.Valid(format) {
		return usagef("--output must be one of table, json, yaml (got %q)", format)
	}
	c.format = format

	c.api = c.newClient(client.Config{BaseURL: c.server, APIKey: c.apiKey})
	return nil
}

// authed returns the client for commands that cannot work anonymously, naming
// both places a key can come from when there is none.
func (c *rootConfig) authed() (client.Client, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("no API key: set OCIDEX_API_KEY or add api-key to %s", configPath())
	}
	return c.api, nil
}

// flagValue returns the flag's value only if it was actually given, so an unset
// flag does not shadow the environment with an empty string.
func flagValue(cmd *cobra.Command, name, value string) string {
	if cmd.Flags().Changed(name) {
		return value
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
