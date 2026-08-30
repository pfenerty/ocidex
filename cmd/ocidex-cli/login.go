package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/pfenerty/ocidex/internal/cliconfig"
	"github.com/pfenerty/ocidex/pkg/client"
)

func newLoginCmd(cfg *rootConfig) *cobra.Command {
	var server, key string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Save a server URL and API key to the config file",
		Long: `Save a server URL and API key to the config file.

Prompts for whatever is not given as a flag, verifies the key by asking the
server who you are, and only then writes ` + "`" + cliconfig.Path() + "`" + ` with
mode 0600. A key that does not work is rejected here rather than at the next
command.

--key exists for non-interactive setup, but prefer OCIDEX_API_KEY in CI: an
argument is visible in the process table and in most runners' command logs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			file, err := cliconfig.Load()
			if err != nil {
				return err
			}

			// One reader for both prompts: a fresh bufio.Reader per prompt would
			// buffer the whole of stdin on the first read and leave the second
			// with nothing.
			in := bufio.NewReader(cmd.InOrStdin())

			if server == "" {
				// The resolved server is the better default than the built-in
				// one: it already accounts for OCIDEX_URL and the existing file.
				server, err = prompt(cmd, in, fmt.Sprintf("Server URL [%s]: ", cfg.server))
				if err != nil {
					return err
				}
			}
			server = firstNonEmpty(server, cfg.server)

			if key == "" {
				key, err = promptSecret(cmd, in, "API key: ")
				if err != nil {
					return err
				}
			}
			if key == "" {
				return usagef("an API key is required; create one in the web UI or with `key create`")
			}

			// Built from the prompted values, not cfg.api, which was constructed
			// from whatever was already configured.
			api := cfg.newClient(client.Config{BaseURL: server, APIKey: key})
			me, err := api.GetCurrentUser(cmd.Context())
			if err != nil {
				return fmt.Errorf("verifying key against %s: %w", server, err)
			}

			file.Server, file.APIKey = server, key
			if err := cliconfig.Save(file); err != nil {
				return err
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "logged in to %s as %s (%s); credentials saved to %s\n",
				server, me.DisplayName, me.Role, cliconfig.Path())
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&server, "server-url", "", "server to log in to (prompted when omitted)")
	f.StringVar(&key, "key", "", "API key (prompted when omitted; prefer OCIDEX_API_KEY in CI)")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored API key",
		Long: `Remove the stored API key.

Only the key: the server URL and output preference are settings, not
credentials, and re-typing them after every logout is friction with no security
benefit. The file is deleted outright once nothing is left in it.

This does not revoke the key server-side — use ` + "`key delete <id>`" + ` for that.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			file, err := cliconfig.Load()
			if err != nil {
				return err
			}

			if file.APIKey == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "no stored API key")
				return nil
			}

			file.APIKey = ""
			if file == (cliconfig.File{}) {
				if err := os.Remove(cliconfig.Path()); err != nil {
					return fmt.Errorf("removing %s: %w", cliconfig.Path(), err)
				}
			} else if err := cliconfig.Save(file); err != nil {
				return err
			}

			// OCIDEX_API_KEY outranks the file, so a logout that leaves it set
			// has not actually logged anyone out.
			if os.Getenv("OCIDEX_API_KEY") != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: OCIDEX_API_KEY is still set and takes precedence")
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "removed the API key from %s\n", cliconfig.Path())
			return nil
		},
	}
}

// prompt writes to stderr and reads one line from in. Stderr so that a prompt
// never contaminates piped output.
func prompt(cmd *cobra.Command, in *bufio.Reader, label string) (string, error) {
	fmt.Fprint(cmd.ErrOrStderr(), label)
	line, err := in.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// promptSecret reads without echoing when the input is a terminal, and falls
// back to a plain line read when it is not — a piped key still works, it just
// was never secret to begin with.
func promptSecret(cmd *cobra.Command, in *bufio.Reader, label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if cmd.InOrStdin() != os.Stdin || !term.IsTerminal(fd) {
		return prompt(cmd, in, label)
	}

	fmt.Fprint(cmd.ErrOrStderr(), label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
